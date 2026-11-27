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
	PolicyToIpfwChains(table string, policyID *proto.PolicyID, policy *proto.Policy, ipVersion uint8) []*ipfw.Chain
	ProfileToIpfwChains(table string, profileID *proto.ProfileID, policy *proto.Profile, ipVersion uint8) (inbound, outbound *ipfw.Chain)
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
		if m.rawEgressOnly {
			chains := m.ruleRenderer.PolicyToIpfwChains("raw", msg.Id, msg.Policy, m.ipVersion)
			outName := rules.PolicyChainNameForTable("raw", rules.PolicyOutboundPfx, msg.Id)
			neededIpfwTable := set.New[string]()
			filteredChains := []*ipfw.Chain(nil)
			for _, chain := range chains {
				if chain.Name == outName {
					filteredChains = append(filteredChains, chain)
					neededIpfwTable.AddAll(chain.IpfwTableNames())
				}
			}
			m.updateNeededIpfwTable(msg.Id, neededIpfwTable)
			m.rawRuleSet.UpdateChains(filteredChains)
			return
		}
		// We can't easily tell whether the policy is in use in a particular table, and, if the policy
		// type gets changed it may move between tables.  Hence, we put the policy into all tables.
		// The ipfw layer will avoid programming it if it is not actually used.
		// IPFW では全テーブルのチェインが1つのルールセットに入るため、テーブルごとに
		// テーブル名付きの名前（cali-R-pi-… / cali-M-pi-… / cali-F-pi-…）で作る。
		m.rawRuleSet.UpdateChains(m.ruleRenderer.PolicyToIpfwChains("raw", msg.Id, msg.Policy, m.ipVersion))
		m.mangleRuleSet.UpdateChains(m.ruleRenderer.PolicyToIpfwChains("mangle", msg.Id, msg.Policy, m.ipVersion))
		m.filterRuleSet.UpdateChains(m.ruleRenderer.PolicyToIpfwChains("filter", msg.Id, msg.Policy, m.ipVersion))
	case *proto.ActivePolicyRemove:
		log.WithField("id", msg.Id).Debug("Removing policy chains")
		m.cleanUpPolicy(msg.Id)
	case *proto.ActiveProfileUpdate:
		if m.rawEgressOnly {
			log.WithField("id", msg.Id).Debug("Ignore non-untracked profile")
			return
		}
		log.WithField("id", msg.Id).Debug("Updating profile chains")
		filterIn, filterOut := m.ruleRenderer.ProfileToIpfwChains("filter", msg.Id, msg.Profile, m.ipVersion)
		m.filterRuleSet.UpdateChains([]*ipfw.Chain{filterIn, filterOut})
		_, mangleOut := m.ruleRenderer.ProfileToIpfwChains("mangle", msg.Id, msg.Profile, m.ipVersion)
		m.mangleRuleSet.UpdateChains([]*ipfw.Chain{mangleOut})
	case *proto.ActiveProfileRemove:
		log.WithField("id", msg.Id).Debug("Removing profile chains")
		m.filterRuleSet.RemoveChainByName(rules.ProfileChainNameForTable("filter", rules.ProfileInboundPfx, msg.Id))
		m.filterRuleSet.RemoveChainByName(rules.ProfileChainNameForTable("filter", rules.ProfileOutboundPfx, msg.Id))
		m.mangleRuleSet.RemoveChainByName(rules.ProfileChainNameForTable("mangle", rules.ProfileOutboundPfx, msg.Id))
	}
}

func (m *policyManager) cleanUpPolicy(id *proto.PolicyID) {
	if m.rawEgressOnly {
		m.updateNeededIpfwTable(id, nil)
	}
	// As above, we need to clean up in all the tables.
	m.filterRuleSet.RemoveChainByName(rules.PolicyChainNameForTable("filter", rules.PolicyInboundPfx, id))
	m.filterRuleSet.RemoveChainByName(rules.PolicyChainNameForTable("filter", rules.PolicyOutboundPfx, id))
	m.mangleRuleSet.RemoveChainByName(rules.PolicyChainNameForTable("mangle", rules.PolicyInboundPfx, id))
	m.mangleRuleSet.RemoveChainByName(rules.PolicyChainNameForTable("mangle", rules.PolicyOutboundPfx, id))
	m.rawRuleSet.RemoveChainByName(rules.PolicyChainNameForTable("raw", rules.PolicyInboundPfx, id))
	m.rawRuleSet.RemoveChainByName(rules.PolicyChainNameForTable("raw", rules.PolicyOutboundPfx, id))
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
