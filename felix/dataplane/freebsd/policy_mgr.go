// Copyright (c) 2016-2023 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package intdataplane

import (
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/set"

	"github.com/projectcalico/calico/felix/ipfw"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/rules"
)

// policyManager simply renders policy/profile updates into ipfw.Chain objects and sends
// them to the dataplane layer.
type policyManager struct {
	rawRuleSet       IpfwRuleSet
	mangleRuleSet    IpfwRuleSet
	filterRuleSet    IpfwRuleSet
	ruleRenderer     policyRenderer
	ipVersion        uint8
	rawEgressOnly    bool
	ipfwTableFilterDirty bool // Only used in "raw only" mode.
	neededIpfwTable     map[proto.PolicyID]set.Set[string]
	ipfwTableCallback   func(neededIpfwTable set.Set[string])
}

type policyRenderer interface {
	PolicyToIpfwChains(policyID *proto.PolicyID, policy *proto.Policy, ipVersion uint8) []*ipfw.Chain
	ProfileToIpfwChains(profileID *proto.ProfileID, policy *proto.Profile, ipVersion uint8) (inbound, outbound *ipfw.Chain)
}

func newPolicyManager(rawRuleSet, mangleRuleSet, filterRuleSet IpfwRuleSet, ruleRenderer policyRenderer, ipVersion uint8) *policyManager {
	return &policyManager{
		rawRuleSet:    rawRuleSet,
		mangleRuleSet: mangleRuleSet,
		filterRuleSet: filterRuleSet,
		ruleRenderer:  ruleRenderer,
		ipVersion:     ipVersion,
	}
}

func newRawEgressPolicyManager(rawRuleSet IpfwRuleSet, ruleRenderer policyRenderer, ipVersion uint8,
	ipfwTableCallback func(neededIpfwTable set.Set[string])) *policyManager {
	return &policyManager{
		rawRuleSet:    rawRuleSet,
		mangleRuleSet: ipfw.NewNoopRuleSet(),
		filterRuleSet: ipfw.NewNoopRuleSet(),
		ruleRenderer:  ruleRenderer,
		ipVersion:     ipVersion,
		rawEgressOnly: true,
		// Make sure we set the filter at start-of-day, even if there are no policies.
		ipfwTableFilterDirty: true,
		neededIpfwTable:     make(map[proto.PolicyID]set.Set[string]),
		ipfwTableCallback:   ipfwTableCallback,
	}
}

func (m *policyManager) OnUpdate(msg interface{}) {
	switch msg := msg.(type) {
	case *proto.ActivePolicyUpdate:
		if m.rawEgressOnly && !msg.Policy.Untracked {
			log.WithField("id", msg.Id).Debug("Clean up non-untracked policy.")
			m.cleanUpPolicy(msg.Id)
			return
		}
		log.WithField("id", msg.Id).Debug("Updating policy chains")
		chains := m.ruleRenderer.PolicyToIpfwChains(msg.Id, msg.Policy, m.ipVersion)
		if m.rawEgressOnly {
			neededIpfwTable := set.New[string]()
			filteredChains := []*ipfw.Chain(nil)
			for _, chain := range chains {
				if strings.Contains(chain.Name, string(rules.PolicyOutboundPfx)) {
					filteredChains = append(filteredChains, chain)
					neededIpfwTable.AddAll(chain.IpfwTableNames())
				}
			}
			chains = filteredChains
			m.updateNeededIpfwTable(msg.Id, neededIpfwTable)
		}
		// We can't easily tell whether the policy is in use in a particular table, and, if the policy
		// type gets changed it may move between tables.  Hence, we put the policy into all tables.
		// The ipfw layer will avoid programming it if it is not actually used.
		m.rawRuleSet.UpdateChains(chains)
		m.mangleRuleSet.UpdateChains(chains)
		m.filterRuleSet.UpdateChains(chains)
	case *proto.ActivePolicyRemove:
		log.WithField("id", msg.Id).Debug("Removing policy chains")
		m.cleanUpPolicy(msg.Id)
	case *proto.ActiveProfileUpdate:
		if m.rawEgressOnly {
			log.WithField("id", msg.Id).Debug("Ignore non-untracked profile")
			return
		}
		log.WithField("id", msg.Id).Debug("Updating profile chains")
		inbound, outbound := m.ruleRenderer.ProfileToIpfwChains(msg.Id, msg.Profile, m.ipVersion)
		m.filterRuleSet.UpdateChains([]*ipfw.Chain{inbound, outbound})
		m.mangleRuleSet.UpdateChains([]*ipfw.Chain{outbound})
	case *proto.ActiveProfileRemove:
		log.WithField("id", msg.Id).Debug("Removing profile chains")
		inName := rules.ProfileChainName(rules.ProfileInboundPfx, msg.Id)
		outName := rules.ProfileChainName(rules.ProfileOutboundPfx, msg.Id)
		m.filterRuleSet.RemoveChainByName(inName)
		m.filterRuleSet.RemoveChainByName(outName)
		m.mangleRuleSet.RemoveChainByName(outName)
	}
}

func (m *policyManager) cleanUpPolicy(id *proto.PolicyID) {
	if m.rawEgressOnly {
		m.updateNeededIpfwTable(id, nil)
	}
	inName := rules.PolicyChainName(rules.PolicyInboundPfx, id)
	outName := rules.PolicyChainName(rules.PolicyOutboundPfx, id)
	// As above, we need to clean up in all the tables.
	m.filterRuleSet.RemoveChainByName(inName)
	m.filterRuleSet.RemoveChainByName(outName)
	m.mangleRuleSet.RemoveChainByName(inName)
	m.mangleRuleSet.RemoveChainByName(outName)
	m.rawRuleSet.RemoveChainByName(inName)
	m.rawRuleSet.RemoveChainByName(outName)
}

func (m *policyManager) updateNeededIpfwTable(id *proto.PolicyID, neededIpfwTable set.Set[string]) {
	if neededIpfwTable != nil {
		m.neededIpfwTable[*id] = neededIpfwTable
	} else {
		delete(m.neededIpfwTable, *id)
	}
	m.ipfwTableFilterDirty = true
}

func (m *policyManager) CompleteDeferredWork() error {
	if !m.rawEgressOnly {
		return nil
	}
	if !m.ipfwTableFilterDirty {
		return nil
	}
	m.ipfwTableFilterDirty = false

	merged := set.New[string]()
	for _, ipfwTable := range m.neededIpfwTable {
		ipfwTable.Iter(func(item string) error {
			merged.Add(item)
			return nil
		})
	}
	m.ipfwTableCallback(merged)
	return nil
}
