// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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

package rules

import (
	"sort"
	"strings"

	"github.com/projectcalico/calico/felix/ipfw"
)

func (r *DefaultRuleRenderer) MakeNatOutgoingRule(protocol string, action ipfw.Action, ipVersion uint8) ipfw.Rule {
	ipConf := r.ipfwTableConfig(ipVersion)
	allIpfwTableName := ipConf.NameForMainIpfwTable(IpfwTableIDNATOutgoingAllPools)
	masqIpfwTableName := ipConf.NameForMainIpfwTable(IpfwTableIDNATOutgoingMasqPools)

	match := ipfw.Match().
		SourceTable(masqIpfwTableName).
		NotDestTable(allIpfwTableName)

	if protocol != "" {
		match = match.Protocol(protocol)
	}

	if r.Config.IpfwNATOutgoingInterfaceFilter != "" {
		match = match.OutInterface(r.Config.IpfwNATOutgoingInterfaceFilter)
	}

	rule := ipfw.Rule{
		Action: action,
		Match:  match,
	}
	return rule
}

func (r *DefaultRuleRenderer) NATOutgoingChain(natOutgoingActive bool, ipVersion uint8) *ipfw.Chain {
	var rules []ipfw.Rule
	if natOutgoingActive {
		var defaultSnatRule ipfw.Action = ipfw.NatAction{}

		rules = []ipfw.Rule{
			r.MakeNatOutgoingRule("", defaultSnatRule, ipVersion),
		}
	}
	return &ipfw.Chain{
		Name:  ChainNATOutgoing,
		Rules: rules,
	}
}

func (r *DefaultRuleRenderer) DNATsToIpfwChains(_ map[string]string) []*ipfw.Chain {
	rules := []ipfw.Rule{}
	return []*ipfw.Chain{{
		Name:  ChainFIPDnat,
		Rules: rules,
	}}
}

func (r *DefaultRuleRenderer) SNATsToIpfwChains(_ map[string]string) []*ipfw.Chain {
	rules := []ipfw.Rule{}
	return []*ipfw.Chain{{
		Name:  ChainFIPSnat,
		Rules: rules,
	}}
}

func (r *DefaultRuleRenderer) BlockedCIDRsToIpfwChains(cidrs []string, ipVersion uint8) []*ipfw.Chain {
	rules := []ipfw.Rule{}
	if r.blockCIDRAction != nil {
		sort.Strings(cidrs)
		for _, cidr := range cidrs {
			if strings.Contains(cidr, ":") == (ipVersion == 6) {
				rules = append(rules, ipfw.Rule{
					Match:  ipfw.Match().DestNet(cidr),
					Action: r.blockCIDRAction,
				})
			}
		}
	}
	return []*ipfw.Chain{{
		Name:  ChainCIDRBlock,
		Rules: rules,
	}}
}
