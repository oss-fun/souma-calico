// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.
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
	"os/exec"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/ipfw"
	. "github.com/projectcalico/calico/felix/ipfw"
	"github.com/projectcalico/calico/felix/proto"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

func (r *DefaultRuleRenderer) StaticFilterTableChains(ipVersion uint8) (chains []*Chain) {
	chains = append(chains, r.StaticFilterForwardChains()...)
	chains = append(chains, r.StaticFilterInputChains(ipVersion)...)
	chains = append(chains, r.StaticFilterOutputChains(ipVersion)...)
	return
}

const (
	ProtoIPIP   = 4
	ProtoTCP    = 6
	ProtoUDP    = 17
	ProtoICMPv6 = 58
)

func (r *DefaultRuleRenderer) StaticFilterInputChains(ipVersion uint8) []*Chain {
	result := []*Chain{}
	result = append(result,
		r.filterInputChain(ipVersion),
		r.filterWorkloadToHostChain(ipVersion),
		r.failsafeInChain("filter", ipVersion),
	)
	return result
}

func (r *DefaultRuleRenderer) acceptAlreadyAccepted() []Rule {
	return []Rule{
		{
			Match:  Match().Tagged(r.IpfwTagAccept),
			Action: r.filterAllowAction,
		},
	}
}

// Forward check chain is to check if a packet belongs to a forwarded traffic or not.
// With kube-proxy running in ipvs mode, both local or forwarded traffic goes through INPUT filter chain.
func (r *DefaultRuleRenderer) StaticFilterInputForwardCheckChain(ipVersion uint8) *Chain {
	var fwRules []Rule
	var portRanges []*proto.PortRange

	// Get ipfwtable name for local host ips.
	nameForIpfwTable := func(id string) string {
		return r.IpfwTableConfigV4.NameForMainIpfwTable(id)
	}
	hostIpfwTable := nameForIpfwTable(IpfwTableIDThisHostIPs)

	fwRules = append(fwRules,
		// If packet belongs to an existing conntrack connection, it does not belong to a forwarded traffic even destination ip is a
		// service ip. This could happen when pod send back response to a local host process accessing a service ip.
		Rule{
			Match:  Match().ConntrackState("established"),
			Action: ReturnAction{},
		},
	)

	// If packet is accessing local host within kubernetes NodePort range, it belongs to a forwarded traffic.
	for _, portSplit := range SplitPortList(portRanges) {
		fwRules = append(fwRules,
			Rule{
				Match: Match().Protocol("tcp").
					DestPortRanges(portSplit).
					DestTable(hostIpfwTable),
				Action:  SkiptoAction{Target: ChainFilterDispatchSetEndPointTag},
				Comment: []string{},
			},
			Rule{
				Match: Match().Protocol("udp").
					DestPortRanges(portSplit).
					DestTable(hostIpfwTable),
				Action:  SkiptoAction{Target: ChainFilterDispatchSetEndPointTag},
				Comment: []string{},
			},
		)
	}

	fwRules = append(fwRules,
		// If packet is accessing non local host ip, it belongs to a forwarded traffic.
		Rule{
			Match:   Match().NotDestTable(hostIpfwTable),
			Action:  CallAction{Target: ChainFilterDispatchSetEndPointTag},
			Comment: []string{},
		},
	)

	result := &Chain{
		Name:  ChainFilterForwardCheck,
		Rules: fwRules,
	}
	if err := result.Organize(); err != nil {
		log.WithField("err", err).Panic("Failed StaticFilterInputForwardCheckChain result Organize")
	}
	return result
}

// With kube-proxy running in ipvs mode, we categorise traffic going through OUTPUT chain into three classes.
// Class 1. forwarded packet originated from a calico workload or host endpoint --> INPUT filter --> OUTPUT filter
// Class 2. forwarded packet originated from a non calico endpoint              --> INPUT filter --> OUTPUT filter
// Class 3. local process originated packet --> OUTPUT filter
// This function handles traffic in Class 1 and Class 2.
func (r *DefaultRuleRenderer) StaticFilterOutputForwardEndpointMarkChain() *Chain {
	var fwRules []Rule

	fwRules = append(fwRules,
		// Only packets that we know are really being forwarded reach this chain. However, since
		// we're called from the OUTPUT chain, we're forbidden from using the input interface match.
		// Instead, we rely on the INPUT chain to mark the packet with a per-endpoint mark value
		// and do our dispatch on that mark value.  So that we don't touch "Class 2" packets, we
		// mark them with mark pattern IpfwTagNonCaliEndpoint and exclude them here.  This
		// prevents the default drop at the end of the dispatch chain from dropping non-Calico
		// traffic.
		Rule{
			Match:  Match().NotTagged(r.IpfwTagEndpoint),
			Action: CallAction{Target: ChainFilterDispatchFromEndPointTag},
		},
	)

	// The packet may be going to a workload interface.  Send any such packets to the normal,
	// interface-name-based dispatch chains.
	for _, prefix := range r.WorkloadIfacePrefixes {
		log.WithField("ifacePrefix", prefix).Debug("Adding workload match rules")
		ifaceMatch := prefix + "*"
		fwRules = append(fwRules,
			Rule{
				Match:  Match().OutInterface(ifaceMatch),
				Action: CallAction{Target: ChainFilterToWorkloadDispatch},
			},
		)
	}

	fwRules = append(fwRules,
		// The packet may be going to a host endpoint, send it to the host endpoint
		// apply-on-forward dispatch chain. That chain returns any packets that are not going to a
		// known host endpoint for further processing.
		Rule{
			Action: CallAction{Target: ChainFilterDispatchToHostEndpointForward},
		},

		// Before we ACCEPT the packet, clear the per-interface mark bit.  This is required because
		// the packet may get encapsulated and pass through ipfw again.  Since the new encapped
		// packet would inherit the mark bits, it would be (incorrectly) treated as a forwarded
		// packet.
		Rule{
			Action: UntagAction{TagNumber: r.IpfwTagEndpoint},
		},

		// If a packet reaches here, one of the following must be true:
		//
		// - it is going to a workload endpoint and it has passed that endpoint's policy
		// - it is going to a host interface with a Calico host endpoint and it has passed that
		//   endpoint's policy
		// - it is going to a host interface with no Calico host endpoint.
		//
		// In the first two cases, the policy will have set the accept bit in the mark and we "own"
		// the packet so it's right for us to ACCEPT it here (unless configured otherwise).  In
		// the other case, we don't own the packet so we always return it to the OUTPUT chain
		// for further processing.
		Rule{
			Match:   Match().Tagged(r.IpfwTagAccept),
			Action:  r.filterAllowAction,
			Comment: []string{},
		},
	)

	result := &Chain{
		Name:  ChainFilterForwardEndpointTag,
		Rules: fwRules,
	}
	if err := result.Organize(); err != nil {
		log.WithField("err", err).Panic("Failed StaticFilterOutputForwardEndpointMarkChain result Organize")
	}
	return result
}

func FilterInputChainAllowWG(ipVersion uint8, r Config, allowAction ipfw.Action) []Rule {
	var inputRules []Rule

	return inputRules
}

func (r *DefaultRuleRenderer) filterInputChain(ipVersion uint8) *Chain {
	var inputRules []Rule

	inputRules = append(inputRules, FilterInputChainAllowWG(ipVersion, r.Config, r.filterAllowAction)...)

	// Apply our policy to packets coming from workload endpoints.
	for _, prefix := range r.WorkloadIfacePrefixes {
		log.WithField("ifacePrefix", prefix).Debug("Adding workload match rules")
		ifaceMatch := prefix + "*"
		inputRules = append(inputRules, Rule{
			Match:  Match().InInterface(ifaceMatch),
			Action: SkiptoAction{Target: ChainFilterWorkloadToHost},
		})
	}

	// Now we only have ingress host endpoint processing to do.  The ingress host endpoint may
	// have already accepted this packet in the raw or mangle table.  In that case, accept the
	// packet immediately here too.
	inputRules = append(inputRules, r.acceptAlreadyAccepted()...)

	// Apply host endpoint policy.
	inputRules = append(inputRules,
		Rule{
			Action: UntagAction{TagNumber: r.allCalicoTagNum()},
		},
		Rule{
			Action: CallAction{Target: ChainFilterDispatchFromHostEndpoint},
		},
		Rule{
			Match:   Match().Tagged(r.IpfwTagAccept),
			Action:  r.filterAllowAction,
			Comment: []string{},
		},
	)

	result := &Chain{
		Name:  ChainFilterInput,
		Rules: inputRules,
	}
	if err := result.Organize(); err != nil {
		log.WithField("err", err).Panic("Failed filterInputChain result Organize")
	}
	return result
}

func ICMPv6Filter(action ipfw.Action) []Rule {
	var rules []Rule

	// For IPv6, we need to allow certain ICMP traffic from workloads in order to act
	// as a router.  Note: we do this before the policy chains, so we're bypassing the egress
	// rules for this traffic.  While that might be unexpected, it makes sure that the user
	// doesn't cut off their own connectivity in subtle ways that they shouldn't have to worry
	// about.
	//
	// - 130: multicast listener query.
	// - 131: multicast listener report.
	// - 132: multicast listener done.
	// - 133: router solicitation, which an endpoint uses to request
	//        configuration information rather than waiting for an
	//        unsolicited router advertisement.
	// - 135: neighbor solicitation.
	// - 136: neighbor advertisement.
	for _, _ = range []uint8{130, 131, 132, 133, 135, 136} {
		rules = append(rules, Rule{
			Match: Match().
				Protocol(ProtoICMPv6),
			Action: action,
		})
	}

	return rules
}

func (r *DefaultRuleRenderer) filterWorkloadToHostChain(ipVersion uint8) *Chain {
	var rules []Rule

	if ipVersion == 6 {
		rules = ICMPv6Filter(r.filterAllowAction)
	}

	if r.OpenStackSpecialCasesEnabled {
		log.Info("Adding OpenStack special-case rules.")
		if ipVersion == 4 && r.OpenStackMetadataIP != nil {
			// For OpenStack compatibility, we support a special-case to allow incoming traffic
			// to the OpenStack metadata IP/port.
			// TODO(smc) Long-term, it'd be nice if the OpenStack plugin programmed a policy to
			// do this instead.
			log.WithField("ip", r.OpenStackMetadataIP).Info(
				"OpenStack metadata IP specified, installing special-case rule.")
			rules = append(rules, Rule{
				Match: Match().
					Protocol("tcp").
					DestNet(r.OpenStackMetadataIP.String()).
					DestPorts(r.OpenStackMetadataPort),
				Action: r.filterAllowAction,
			})
		}

		// Again, for OpenStack compatibility, allow certain protocols.
		// TODO(smc) Long-term, it'd be nice if the OpenStack plugin programmed a policy to
		// do this instead.
		dhcpSrcPort := uint16(68)
		dhcpDestPort := uint16(67)
		if ipVersion == 6 {
			dhcpSrcPort = uint16(546)
			dhcpDestPort = uint16(547)
		}
		dnsDestPort := uint16(53)
		rules = append(rules,
			Rule{
				Match: Match().
					Protocol("udp").
					SourcePorts(dhcpSrcPort).
					DestPorts(dhcpDestPort),
				Action: r.filterAllowAction,
			},
			Rule{
				Match: Match().
					Protocol("udp").
					DestPorts(dnsDestPort),
				Action: r.filterAllowAction,
			},
		)
	}

	// Now send traffic to the policy chains to apply the egress policy.
	rules = append(rules, Rule{
		Action: CallAction{Target: ChainFilterFromWorkloadDispatch},
	})

	// skipto対象chainとしての処理
	rules = append(rules, Rule{
		Action: SkiptoAction{RuleNumber: 65534},
	})

	result := &Chain{
		Name:  ChainFilterWorkloadToHost,
		Rules: rules,
	}
	if err := result.Organize(); err != nil {
		log.WithField("err", err).Panic("Failed filterWorkloadToHostChain result Organize")
	}
	return result
}

func (r *DefaultRuleRenderer) failsafeInChain(table string, ipVersion uint8) *Chain {
	rules := []Rule{}

	for _, protoPort := range r.Config.FailsafeInboundHostPorts {
		rule := Rule{
			Match: Match().
				Protocol(protoPort.Protocol).
				DestPorts(protoPort.Port),
			Action: AllowAction{},
		}

		if protoPort.Net != "" {
			ip, _, err := cnet.ParseCIDROrIP(protoPort.Net)
			if err != nil {
				log.WithError(err).Error("Failed to parse CIDR in inbound failsafe rule. Skipping failsafe rule")
				continue
			}
			if int(ipVersion) == ip.Version() {
				rule.Match = Match().
					Protocol(protoPort.Protocol).
					DestPorts(protoPort.Port).
					SourceNet(protoPort.Net)
			} else {
				continue // don't add the rule
			}
		}
		rules = append(rules, rule)
	}

	if table == "raw" {
		// We're in the raw table, before conntrack, so we need to allow response traffic.
		// Otherwise, it could fall through to some doNotTrack policy and half of the connection
		// would get untracked.  If we ACCEPT here then the traffic falls through to the filter
		// table, where it'll only be accepted if there's a conntrack entry.
		for _, protoPort := range r.Config.FailsafeOutboundHostPorts {
			rule := Rule{
				Match: Match().
					Protocol(protoPort.Protocol).
					SourcePorts(protoPort.Port),
				Action: AllowAction{},
			}

			if protoPort.Net != "" {
				ip, _, err := cnet.ParseCIDROrIP(protoPort.Net)
				if err != nil {
					log.WithError(err).Error("Failed to parse CIDR in inbound failsafe rule. Skipping failsafe rule")
					continue
				}
				if int(ipVersion) == ip.Version() {
					rule.Match = Match().
						Protocol(protoPort.Protocol).
						SourcePorts(protoPort.Port).
						SourceNet(protoPort.Net)
				} else {
					continue // don't add the rule
				}
			}
			rules = append(rules, rule)
		}
	}

	var cn string
	switch table {
	case "filter":
		cn = ChainFilterFailsafeIn
	case "mangle":
		cn = ChainMangleFailsafeIn
	case "raw":
		cn = ChainRawFailsafeIn
	default:
		log.Panicf("failsafeInChain failed: No such Table: %s", table)
	}

	result := &Chain{
		Name:  cn,
		Rules: rules,
	}
	if err := result.Organize(); err != nil {
		log.WithField("err", err).Panic("Failed failsafeInChain result Organize")
	}
	return result
}

func (r *DefaultRuleRenderer) failsafeOutChain(table string, ipVersion uint8) *Chain {
	rules := []Rule{}

	for _, protoPort := range r.Config.FailsafeOutboundHostPorts {
		rule := Rule{
			Match: Match().
				Protocol(protoPort.Protocol).
				DestPorts(protoPort.Port),
			Action: AllowAction{},
		}

		if protoPort.Net != "" {
			ip, _, err := cnet.ParseCIDROrIP(protoPort.Net)
			if err != nil {
				log.WithError(err).Error("Failed to parse CIDR in outbound failsafe rule. Skipping failsafe rule")
				continue
			}
			if int(ipVersion) == ip.Version() {
				rule.Match = Match().
					Protocol(protoPort.Protocol).
					DestPorts(protoPort.Port).
					DestNet(protoPort.Net)
			} else {
				continue // don't add the rule
			}
		}
		rules = append(rules, rule)
	}

	if table == "raw" {
		// We're in the raw table, before conntrack, so we need to allow response traffic.
		// Otherwise, it could fall through to some doNotTrack policy and half of the connection
		// would get untracked.  If we ACCEPT here then the traffic falls through to the filter
		// table, where it'll only be accepted if there's a conntrack entry.
		for _, protoPort := range r.Config.FailsafeInboundHostPorts {
			rule := Rule{
				Match: Match().
					Protocol(protoPort.Protocol).
					SourcePorts(protoPort.Port),
				Action: AllowAction{},
			}

			if protoPort.Net != "" {
				ip, _, err := cnet.ParseCIDROrIP(protoPort.Net)
				if err != nil {
					log.WithError(err).Error("Failed to parse CIDR in outbound failsafe rule. Skipping failsafe rule")
					continue
				}
				if int(ipVersion) == ip.Version() {
					rule.Match = Match().
						Protocol(protoPort.Protocol).
						SourcePorts(protoPort.Port).
						DestNet(protoPort.Net)
				} else {
					continue // don't add the rule
				}
			}
			rules = append(rules, rule)
		}
	}

	var cn string
	switch table {
	case "filter":
		cn = ChainFilterFailsafeOut
	case "mangle":
		cn = ChainMangleFailsafeOut
	case "raw":
		cn = ChainRawFailsafeOut
	default:
		log.Panicf("failsafeOutChain failed: No such Table: %s", table)
	}

	result := &Chain{
		Name:  cn,
		Rules: rules,
	}
	if err := result.Organize(); err != nil {
		log.WithField("err", err).Panic("Failed failsafeOutChain result Organize")
	}
	return result
}

func (r *DefaultRuleRenderer) StaticFilterForwardChains() []*Chain {
	rules := []Rule{}

	// Rules for filter forward chains dispatches the packet to our dispatch chains if it is going
	// to/from an interface that we're responsible for.  Note: the dispatch chains represent "allow"
	// by returning to this chain for further processing; this is required to handle traffic that
	// is going between endpoints on the same host.  In that case we need to apply the egress policy
	// for one endpoint and the ingress policy for the other.
	//
	// Packets will be accepted if they passed through both workload and host endpoint policy
	// and were returned.

	// Jump to from-host-endpoint dispatch chains.
	rules = append(rules,
		Rule{
			// we're clearing all our mark bits to minimise non-determinism caused by rules in other chains.
			// We exclude the accept bit because we use that to communicate from the raw/pre-dnat chains.
			Action: UntagAction{TagNumber: r.IpfwTagAccept},
		},
		Rule{
			// Apply forward policy for the incoming Host endpoint if accept bit is clear which means the packet
			// was not accepted in a previous raw or pre-DNAT chain.
			Match:  Match().Tagged(r.IpfwTagAccept),
			Action: CallAction{Target: ChainFilterDispatchFromHostEndPointForward},
		},
	)

	// Jump to workload dispatch chains.
	for _, prefix := range r.WorkloadIfacePrefixes {
		log.WithField("ifacePrefix", prefix).Debug("Adding workload match rules")
		ifaceMatch := prefix + "+"
		rules = append(rules,
			Rule{
				Match:  Match().InInterface(ifaceMatch),
				Action: CallAction{Target: ChainFilterFromWorkloadDispatch},
			},
			Rule{
				Match:  Match().OutInterface(ifaceMatch),
				Action: CallAction{Target: ChainFilterToWorkloadDispatch},
			},
		)
	}

	// Jump to to-host-endpoint dispatch chains.
	rules = append(rules,
		Rule{
			// Apply forward policy for the outgoing host endpoint.
			Action: CallAction{Target: ChainFilterDispatchToHostEndpointForward},
		},
	)

	// Jump to chain for blocking service CIDR loops.
	rules = append(rules,
		Rule{
			Action: CallAction{Target: ChainFilterCIDRBlock},
		},
	)

	results := []*Chain{{
		Name:  ChainFilterForward,
		Rules: rules,
	}}
	for _, v := range results {
		if err := v.Organize(); err != nil {
			log.WithField("err", err).Panic("Failed StaticFilterForwardChains result Organize")
		}
	}
	return results
}

// StaticFilterForwardAppendRules returns rules which should be statically appended to the end of the filter
// table's forward chain.
func (r *DefaultRuleRenderer) StaticFilterForwardAppendRules() []Rule {
	return []Rule{
		{
			Number:  35,
			Match:   Match().Tagged(r.IpfwTagAccept),
			Action:  r.filterAllowAction,
			Comment: []string{},
		},

		// Set IpfwTagAccept bit here, to indicate to our mangle-POSTROUTING chain that this is
		// forwarded traffic and should not be subject to normal host endpoint policy.
		{
			Number: 36,
			Action: TagAction{TagNumber: r.IpfwTagAccept},
		},
	}
}

func (r *DefaultRuleRenderer) StaticFilterOutputChains(ipVersion uint8) []*Chain {
	result := []*Chain{}
	result = append(result,
		r.filterOutputChain(ipVersion),
		r.failsafeOutChain("filter", ipVersion),
	)

	return result
}

func (r *DefaultRuleRenderer) filterOutputChain(ipVersion uint8) *Chain {
	var rules []Rule

	// Accept immediately if we've already accepted this packet in the raw or mangle table.
	rules = append(rules, r.acceptAlreadyAccepted()...)

	// We don't currently police host -> endpoint according to the endpoint's ingress policy.
	// That decision is based on pragmatism; it's generally very useful to be able to contact
	// any local workload from the host and policing the traffic doesn't really protect
	// against host compromise.  If a host is compromised, then the rules could be removed!
	// However, we do apply policy to workload ingress traffic if it belongs to an IPVS connection.
	for _, prefix := range r.WorkloadIfacePrefixes {
		// If the packet is going to a workload endpoint, apply workload ingress policy if traffic
		// belongs to an IPVS connection and return at the end.
		log.WithField("ifacePrefix", prefix).Debug("Adding workload match rules")
		ifaceMatch := prefix + "+"
		rules = append(rules,
			Rule{
				// if packet goes to a workload endpoint. set return action properly.
				Match:  Match().OutInterface(ifaceMatch),
				Action: ReturnAction{},
			},
		)
	}

	// Apply host endpoint policy to traffic that has not been DNAT'd.  In the DNAT case we
	// can't correctly apply policy here because the packet's OIF is still the OIF from a
	// routing lookup based on the pre-DNAT destination IP; Linux will shortly update it based
	// on the new destination IP, but that hasn't happened yet.  Instead, in the DNAT case, we
	// apply host endpoint in the mangle POSTROUTING chain; see StaticManglePostroutingChain for
	// that.
	rules = append(rules,
		Rule{
			Action: UntagAction{TagNumber: r.allCalicoTagNum()},
		},
		Rule{
			Match:  Match(),
			Action: CallAction{Target: ChainFilterDispatchToHostEndpoint},
		},
		Rule{
			Match:   Match().Tagged(r.IpfwTagAccept),
			Action:  r.filterAllowAction,
			Comment: []string{},
		},
	)

	result := &Chain{
		Name:  ChainFilterOutput,
		Rules: rules,
	}
	if err := result.Organize(); err != nil {
		log.WithField("err", err).Panic("Failed filterOutputChain result Organize")
	}
	return result
}

func (r *DefaultRuleRenderer) StaticNATTableChains(ipVersion uint8) (chains []*Chain) {
	StaticNATConfig()
	chains = append(chains, r.StaticNATPostroutingChains(ipVersion)...)
	return
}

func (r *DefaultRuleRenderer) StaticNATPreroutingChains(ipVersion uint8) []*Chain {
	chains := []*Chain{}
	return chains
}

func (r *DefaultRuleRenderer) StaticNATPostroutingChains(ipVersion uint8) []*Chain {
	rules := []Rule{
		{
			Action: CallAction{Target: ChainNATOutgoing},
		},
	}

	results := []*Chain{{
		Name:  ChainNATPostrouting,
		Rules: rules,
	}}
	for _, v := range results {
		if err := v.Organize(); err != nil {
			log.WithField("err", err).Panic("Failed StaticNATPostroutingChains result Organize")
		}
	}
	return results
}

func (r *DefaultRuleRenderer) StaticNATOutputChains(ipVersion uint8) []*Chain {
	chains := []*Chain{}
	return chains
}

func StaticNATConfig() {
	// TODO
	// テスト環境にのみ対応
	// 環境変数や引数から外への通信をするIF名を取得できるようにする
	nc := NewNatConfig(1).Iface("em0").UnregOnly().Reset()

	if err := exec.Command("ipfw", nc.CmdString()).Run(); err != nil {
		log.WithError(err).Panic("StaticNATConfig Failed.")
	}
}

func (r *DefaultRuleRenderer) StaticMangleTableChains(ipVersion uint8) []*Chain {
	var chains []*Chain

	chains = append(chains,
		r.failsafeInChain("mangle", ipVersion),
		r.failsafeOutChain("mangle", ipVersion),
		r.StaticManglePreroutingChain(ipVersion),
		r.StaticManglePostroutingChain(ipVersion),
	)

	return chains
}

func (r *DefaultRuleRenderer) StaticManglePreroutingChain(ipVersion uint8) *Chain {
	rules := []Rule{}

	// ACCEPT or RETURN immediately if packet matches an existing connection.  Note that we also
	// have a rule like this at the start of each pre-endpoint chain; the functional difference
	// with placing this rule here is that it will also apply to packets that may be unrelated
	// to Calico (i.e. not to or from Calico workloads, and not via Calico host endpoints).  We
	// think this is appropriate in the mangle table here - whereas we don't have a rule like
	// this in the filter table - because the mangle table is generally not used (except by us)
	// for dropping packets, so it is very unlikely that we would be circumventing someone
	// else's rule to drop a packet.  (And in that case, the user can configure
	// IpfwMangleAllowAction to be RETURN.)
	rules = append(rules,
		Rule{
			Match:  Match().ConntrackState("established"),
			Action: r.mangleAllowAction,
		},
	)

	// Or if we've already accepted this packet in the raw table.
	rules = append(rules,
		Rule{
			Match:  Match().Tagged(r.IpfwTagAccept),
			Action: r.mangleAllowAction,
		},
	)

	// Now dispatch to host endpoint chain for the incoming interface.
	rules = append(rules,
		Rule{
			Action: CallAction{Target: ChainMangleDispatchFromHostEndpoint},
		},
		// Following that...  If the packet was explicitly allowed by a pre-DNAT policy, it
		// will have MarkAccept set.  If the packet was denied, it will have been dropped
		// already.  If the incoming interface isn't one that we're policing, or the packet
		// isn't governed by any pre-DNAT policy on that interface, it will fall through to
		// here without any Calico bits set.

		// In the MarkAccept case, we ACCEPT or RETURN according to
		// IpfwMangleAllowAction.
		Rule{
			Match:   Match().Tagged(r.IpfwTagAccept),
			Action:  r.mangleAllowAction,
			Comment: []string{},
		},
	)

	result := &Chain{
		Name:  ChainManglePrerouting,
		Rules: rules,
	}
	if err := result.Organize(); err != nil {
		log.WithField("err", err).Panic("Failed StaticManglePreroutingChain result Organize")
	}
	return result
}

func (r *DefaultRuleRenderer) StaticManglePostroutingChain(ipVersion uint8) *Chain {
	rules := []Rule{}

	// Note, we use RETURN as the Allow action in this chain, rather than ACCEPT because the
	// mangle table is typically used, if at all, for packet manipulations that might need to
	// apply to our allowed traffic.

	// Allow immediately if IpfwTagAccept is set.  Our filter-FORWARD chain sets this for
	// any packets that reach the end of that chain.  The principle is that we don't want to
	// apply normal host endpoint policy to forwarded traffic.
	rules = append(rules, Rule{
		Match:  Match().Tagged(r.IpfwTagAccept),
		Action: ReturnAction{},
	})

	// At this point we know that the packet is not forwarded, so it must be originated by a
	// host-based process or host-networked pod.

	// The similar sequence in filterOutputChain has rules here to allow IPIP and VXLAN traffic.
	// We don't need those rules here because the encapsulated traffic won't match `--ctstate
	// DNAT` and so we won't try applying HEP policy to it anyway.

	// The similar sequence in filterOutputChain has rules here to detect traffic to local
	// workloads, and to return early in that case.  We don't need those rules here because
	// ChainDispatchToHostEndpoint also checks for traffic to a local workload, and avoids
	// applying any host endpoint policy in that case.  Search for "Skip egress WHEP" in
	// dispatch.go, to see that.

	// Apply host endpoint policy to non-forwarded traffic that has been DNAT'd.  We do this
	// here, rather than in filter-OUTPUT, because Linux is weird: when a host-originated packet
	// is DNAT'd (typically in nat-OUTPUT), its destination IP is changed immediately, but Linux
	// does not recalculate the outgoing interface (OIF) until AFTER the filter-OUTPUT chain.
	// The OIF has been recalculated by the time we hit THIS chain (mangle-POSTROUTING), so we
	// can reliably apply host endpoint policy here.
	rules = append(rules,
		Rule{
			Action: UntagAction{TagNumber: r.allCalicoTagNum()},
		},
		Rule{
			Match:  Match().ConntrackState("established"), // DNAT
			Action: CallAction{Target: ChainMangleDispatchToHostEndpoint},
		},
		Rule{
			Match:   Match().Tagged(r.IpfwTagAccept),
			Action:  ReturnAction{},
			Comment: []string{},
		},
	)

	result := &Chain{
		Name:  ChainManglePostrouting,
		Rules: rules,
	}
	if err := result.Organize(); err != nil {
		log.WithField("err", err).Panic("Failed StaticManglePostroutingChain result Organize")
	}
	return result
}

func (r *DefaultRuleRenderer) StaticRawTableChains(ipVersion uint8) []*Chain {
	return []*Chain{
		r.failsafeInChain("raw", ipVersion),
		r.failsafeOutChain("raw", ipVersion),
		r.StaticRawPreroutingChain(ipVersion),
		r.StaticRawOutputChain(0),
	}
}

func (r *DefaultRuleRenderer) StaticRawPreroutingChain(ipVersion uint8) *Chain {
	rules := []Rule{}

	// For safety, clear all our mark bits before we start.  (We could be in append mode and
	// another process' rules could have left the mark bit set.)
	rules = append(rules,
		Rule{Action: UntagAction{TagNumber: r.allCalicoTagNum()}},
	)

	// Set a mark on the packet if it's from a workload interface.
	tagFromWorkload := r.IpfwTagScratch0
	for _, ifacePrefix := range r.WorkloadIfacePrefixes {
		rules = append(rules, Rule{
			Match:  Match().InInterface(ifacePrefix + "+"),
			Action: TagAction{TagNumber: tagFromWorkload},
		})
	}

	rules = append(rules,
		// Send non-workload traffic to the untracked policy chains.
		Rule{Match: Match().NotTagged(tagFromWorkload),
			Action: CallAction{Target: ChainRawDispatchFromHostEndpoint}},
		// Then, if the packet was marked as allowed, accept it.  Packets also return here
		// without the mark bit set if the interface wasn't one that we're policing.  We
		// let those packets fall through to the user's policy.
		Rule{Match: Match().Tagged(r.IpfwTagAccept),
			Action: AllowAction{}},
	)

	result := &Chain{
		Name:  ChainRawPrerouting,
		Rules: rules,
	}
	if err := result.Organize(); err != nil {
		log.WithField("err", err).Panic("Failed StaticRawPreroutingChain result Organize")
	}
	return result
}

func (r *DefaultRuleRenderer) allCalicoTagNum() uint16 {
	return r.IpfwTagAccept |
		r.IpfwTagPass |
		r.IpfwTagScratch0 |
		r.IpfwTagScratch1
}

func (r *DefaultRuleRenderer) StaticRawOutputChain(tcBypassTag uint16) *Chain {
	rules := []Rule{
		// For safety, clear all our mark bits before we start.  (We could be in
		// append mode and another process' rules could have left the mark bit set.)
		{Action: UntagAction{TagNumber: r.allCalicoTagNum()}},
		// Then, jump to the untracked policy chains.
		{Action: CallAction{Target: ChainRawDispatchToHostEndpoint}},
		// Then, if the packet was marked as allowed, accept it.  Packets also
		// return here without the mark bit set if the interface wasn't one that
		// we're policing.
	}
	if tcBypassTag == 0 {
		rules = append(rules, []Rule{
			{Match: Match().Tagged(r.IpfwTagAccept),
				Action: AllowAction{}},
		}...)
	} else {
		rules = append(rules, []Rule{
			{Match: Match().Tagged(r.IpfwTagAccept),
				Action: TagAction{TagNumber: tcBypassTag}},
			{Match: Match().Tagged(tcBypassTag),
				Action: AllowAction{}},
		}...)
	}
	result := &Chain{
		Name:  ChainRawOutput,
		Rules: rules,
	}
	if err := result.Organize(); err != nil {
		log.WithField("err", err).Panic("Failed StaticRawOutputChain result Organize")
	}
	return result
}
