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
	"fmt"
	"sort"
	"strings"

	"github.com/projectcalico/calico/felix/ipfw"
)

func (r *DefaultRuleRenderer) MakeNatOutgoingRule(protocol string, action ipfw.Action, ipVersion uint8) ipfw.Rule {
	return r.makeNATOutgoingRuleIpfw(ipVersion, protocol, action)
}

func (r *DefaultRuleRenderer) makeNATOutgoingRuleIpfw(ipVersion uint8, protocol string, action ipfw.Action) ipfw.Rule {
	ipConf := r.ipSetConfig(ipVersion)
	allIPsSetName := ipConf.NameForMainIPSet(IPSetIDNATOutgoingAllPools)
	masqIPsSetName := ipConf.NameForMainIPSet(IPSetIDNATOutgoingMasqPools)

	match := ipfw.Match().
		SourceIPSet(masqIPsSetName).
		NotDestIPSet(allIPsSetName)

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
		var defaultSnatRule ipfw.Action = ipfw.MasqAction{}
		if r.Config.NATOutgoingAddress != nil {
			defaultSnatRule = ipfw.SNATAction{ToAddr: r.Config.NATOutgoingAddress.String()}
		}

		if r.Config.NATPortRange.MaxPort > 0 {
			toPorts := fmt.Sprintf("%d-%d", r.Config.NATPortRange.MinPort, r.Config.NATPortRange.MaxPort)
			var portRangeSnatRule ipfw.Action = ipfw.MasqAction{ToPorts: toPorts}
			if r.Config.NATOutgoingAddress != nil {
				toAddress := fmt.Sprintf("%s:%s", r.Config.NATOutgoingAddress.String(), toPorts)
				portRangeSnatRule = ipfw.SNATAction{ToAddr: toAddress}
			}
			rules = []ipfw.Rule{
				r.MakeNatOutgoingRule("tcp", portRangeSnatRule, ipVersion),
				r.MakeNatOutgoingRule("tcp", ipfw.ReturnAction{}, ipVersion),
				r.MakeNatOutgoingRule("udp", portRangeSnatRule, ipVersion),
				r.MakeNatOutgoingRule("udp", ipfw.ReturnAction{}, ipVersion),
				r.MakeNatOutgoingRule("", defaultSnatRule, ipVersion),
			}
		} else {
			rules = []ipfw.Rule{
				r.MakeNatOutgoingRule("", defaultSnatRule, ipVersion),
			}
		}
	}
	return &ipfw.Chain{
		Name:  ChainNATOutgoing,
		Rules: rules,
	}
}

func (r *DefaultRuleRenderer) DNATsToIpfwChains(dnats map[string]string) []*ipfw.Chain {
	// Extract and sort map keys so we can program rules in a determined order.
	sortedExtIps := make([]string, 0, len(dnats))
	for extIp := range dnats {
		sortedExtIps = append(sortedExtIps, extIp)
	}
	sort.Strings(sortedExtIps)

	rules := []ipfw.Rule{}
	for _, extIp := range sortedExtIps {
		intIp := dnats[extIp]
		rules = append(rules, ipfw.Rule{
			Match:  ipfw.Match().DestNet(extIp),
			Action: ipfw.DNATAction{DestAddr: intIp},
		})
	}
	return []*ipfw.Chain{{
		Name:  ChainFIPDnat,
		Rules: rules,
	}}
}

func (r *DefaultRuleRenderer) SNATsToIpfwChains(snats map[string]string) []*ipfw.Chain {
	// Extract and sort map keys so we can program rules in a determined order.
	sortedIntIps := make([]string, 0, len(snats))
	for intIp := range snats {
		sortedIntIps = append(sortedIntIps, intIp)
	}
	sort.Strings(sortedIntIps)

	rules := []ipfw.Rule{}
	for _, intIp := range sortedIntIps {
		extIp := snats[intIp]
		rules = append(rules, ipfw.Rule{
			Match:  ipfw.Match().DestNet(intIp).SourceNet(intIp),
			Action: ipfw.SNATAction{ToAddr: extIp},
		})
	}
	return []*ipfw.Chain{{
		Name:  ChainFIPSnat,
		Rules: rules,
	}}
}

func (r *DefaultRuleRenderer) BlockedCIDRsToIpfwChains(cidrs []string, ipVersion uint8) []*ipfw.Chain {
	rules := []ipfw.Rule{}
	if r.blockCIDRAction != nil {
		// Sort CIDRs so we can program rules in a determined order.
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
