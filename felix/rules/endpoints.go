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

package rules

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/sha3"

	"github.com/projectcalico/calico/felix/hashutils"
	. "github.com/projectcalico/calico/felix/ipfw"
	"github.com/projectcalico/calico/felix/proto"
)

const (
	alwaysAllowVXLANEncap = true
	alwaysAllowIPIPEncap  = true
)

func (r *DefaultRuleRenderer) WorkloadEndpointToIpfwChains(
	ifaceName string,
	epMarkMapper EndpointTagMapper,
	adminUp bool,
	ingressPolicies []*PolicyGroup,
	egressPolicies []*PolicyGroup,
	profileIDs []string,
) []*Chain {
	allowVXLANEncapFromWorkloads := r.Config.AllowVXLANPacketsFromWorkloads
	allowIPIPEncapFromWorkloads := r.Config.AllowIPIPPacketsFromWorkloads
	result := []*Chain{}
	result = append(result,
		// Chain for traffic _to_ the endpoint.
		r.endpointIpfwChain(
			ingressPolicies,
			profileIDs,
			ifaceName,
			PolicyInboundPfx,
			ProfileInboundPfx,
			WorkloadToEndpointPfx,
			"", // No fail-safe chains for workloads.
			chainTypeNormal,
			adminUp,
			r.filterAllowAction, // Workload endpoint chains are only used in the filter table
			alwaysAllowVXLANEncap,
			alwaysAllowIPIPEncap,
		),
		// Chain for traffic _from_ the endpoint.
		// Encap traffic is blocked by default from workload endpoints
		// unless explicitly overridden.
		r.endpointIpfwChain(
			egressPolicies,
			profileIDs,
			ifaceName,
			PolicyOutboundPfx,
			ProfileOutboundPfx,
			WorkloadFromEndpointPfx,
			"", // No fail-safe chains for workloads.
			chainTypeNormal,
			adminUp,
			r.filterAllowAction, // Workload endpoint chains are only used in the filter table
			allowVXLANEncapFromWorkloads,
			allowIPIPEncapFromWorkloads,
		),
	)

	return result
}

func (r *DefaultRuleRenderer) HostEndpointToFilterChains(
	ifaceName string,
	epTagMapper EndpointTagMapper,
	ingressPolicies []*PolicyGroup,
	egressPolicies []*PolicyGroup,
	ingressForwardPolicies []*PolicyGroup,
	egressForwardPolicies []*PolicyGroup,
	profileIDs []string,
) []*Chain {
	log.WithField("ifaceName", ifaceName).Debug("Rendering filter host endpoint chain.")
	result := []*Chain{}
	result = append(result,
		// Chain for output traffic _to_ the endpoint.
		r.endpointIpfwChain(
			egressPolicies,
			profileIDs,
			ifaceName,
			PolicyOutboundPfx,
			ProfileOutboundPfx,
			HostToEndpointPfx,
			ChainFailsafeOut,
			chainTypeNormal,
			true, // Host endpoints are always admin up.
			r.filterAllowAction,
			alwaysAllowVXLANEncap,
			alwaysAllowIPIPEncap,
		),
		// Chain for input traffic _from_ the endpoint.
		r.endpointIpfwChain(
			ingressPolicies,
			profileIDs,
			ifaceName,
			PolicyInboundPfx,
			ProfileInboundPfx,
			HostFromEndpointPfx,
			ChainFailsafeIn,
			chainTypeNormal,
			true, // Host endpoints are always admin up.
			r.filterAllowAction,
			alwaysAllowVXLANEncap,
			alwaysAllowIPIPEncap,
		),
		// Chain for forward traffic _to_ the endpoint.
		r.endpointIpfwChain(
			egressForwardPolicies,
			profileIDs,
			ifaceName,
			PolicyOutboundPfx,
			ProfileOutboundPfx,
			HostToEndpointForwardPfx,
			"", // No fail-safe chains for forward traffic.
			chainTypeForward,
			true, // Host endpoints are always admin up.
			r.filterAllowAction,
			alwaysAllowVXLANEncap,
			alwaysAllowIPIPEncap,
		),
		// Chain for forward traffic _from_ the endpoint.
		r.endpointIpfwChain(
			ingressForwardPolicies,
			profileIDs,
			ifaceName,
			PolicyInboundPfx,
			ProfileInboundPfx,
			HostFromEndpointForwardPfx,
			"", // No fail-safe chains for forward traffic.
			chainTypeForward,
			true, // Host endpoints are always admin up.
			r.filterAllowAction,
			alwaysAllowVXLANEncap,
			alwaysAllowIPIPEncap,
		),
	)

	return result
}

func (r *DefaultRuleRenderer) HostEndpointToMangleEgressChains(
	ifaceName string,
	egressPolicies []*PolicyGroup,
	profileIDs []string,
) []*Chain {
	log.WithField("ifaceName", ifaceName).Debug("Render host endpoint mangle egress chain.")
	return []*Chain{
		// Chain for output traffic _to_ the endpoint.  Note, we use RETURN here rather than
		// ACCEPT because the mangle table is typically used, if at all, for packet
		// manipulations that might need to apply to our allowed traffic.
		r.endpointIpfwChain(
			egressPolicies,
			profileIDs,
			ifaceName,
			PolicyOutboundPfx,
			ProfileOutboundPfx,
			HostToEndpointPfx,
			ChainFailsafeOut,
			chainTypeNormal,
			true, // Host endpoints are always admin up.
			ReturnAction{},
			alwaysAllowVXLANEncap,
			alwaysAllowIPIPEncap,
		),
	}
}

func (r *DefaultRuleRenderer) HostEndpointToRawEgressChain(
	ifaceName string,
	egressPolicies []*PolicyGroup,
) *Chain {
	log.WithField("ifaceName", ifaceName).Debug("Rendering raw (untracked) host endpoint egress chain.")
	return r.endpointIpfwChain(
		egressPolicies,
		nil, // We don't render profiles into the raw table.
		ifaceName,
		PolicyOutboundPfx,
		ProfileOutboundPfx,
		HostToEndpointPfx,
		ChainFailsafeOut,
		chainTypeUntracked,
		true, // Host endpoints are always admin up.
		AllowAction{},
		alwaysAllowVXLANEncap,
		alwaysAllowIPIPEncap,
	)
}

func (r *DefaultRuleRenderer) HostEndpointToRawChains(
	ifaceName string,
	ingressPolicies []*PolicyGroup,
	egressPolicies []*PolicyGroup,
) []*Chain {
	log.WithField("ifaceName", ifaceName).Debug("Rendering raw (untracked) host endpoint chain.")
	return []*Chain{
		// Chain for traffic _to_ the endpoint.
		r.HostEndpointToRawEgressChain(ifaceName, egressPolicies),
		// Chain for traffic _from_ the endpoint.
		r.endpointIpfwChain(
			ingressPolicies,
			nil, // We don't render profiles into the raw table.
			ifaceName,
			PolicyInboundPfx,
			ProfileInboundPfx,
			HostFromEndpointPfx,
			ChainFailsafeIn,
			chainTypeUntracked,
			true, // Host endpoints are always admin up.
			AllowAction{},
			alwaysAllowVXLANEncap,
			alwaysAllowIPIPEncap,
		),
	}
}

func (r *DefaultRuleRenderer) HostEndpointToMangleIngressChains(
	ifaceName string,
	preDNATPolicies []*PolicyGroup,
) []*Chain {
	log.WithField("ifaceName", ifaceName).Debug("Rendering pre-DNAT host endpoint chain.")
	return []*Chain{
		// Chain for traffic _from_ the endpoint.  Pre-DNAT policy does not apply to
		// outgoing traffic through a host endpoint.
		r.endpointIpfwChain(
			preDNATPolicies,
			nil, // We don't render profiles into the raw table.
			ifaceName,
			PolicyInboundPfx,
			ProfileInboundPfx,
			HostFromEndpointPfx,
			ChainFailsafeIn,
			chainTypePreDNAT,
			true, // Host endpoints are always admin up.
			r.mangleAllowAction,
			alwaysAllowVXLANEncap,
			alwaysAllowIPIPEncap,
		),
	}
}

type endpointChainType int

const (
	chainTypeNormal endpointChainType = iota
	chainTypeUntracked
	chainTypePreDNAT
	chainTypeForward
)

func (r *DefaultRuleRenderer) endpointSetTagChain(
	name string,
	epTagMapper EndpointTagMapper,
	endpointPrefix string,
) *Chain {
	rules := []Rule{}
	chainName := EndpointChainName(endpointPrefix, name)

	if endPointTag, err := epTagMapper.GetEndpointTag(name); err == nil {
		// Set endpoint mark.
		rules = append(rules, Rule{
			Action: TagAction{
				TagNumber: endPointTag,
			},
		})
	}
	return &Chain{
		Name:  chainName,
		Rules: rules,
	}
}
func (r *DefaultRuleRenderer) PolicyGroupToIpfwChains(group *PolicyGroup) []*Chain {
	rules := make([]Rule, 0, len(group.PolicyNames)*2-1)
	polChainPrefix := PolicyInboundPfx
	if group.Direction == PolicyDirectionOutbound {
		polChainPrefix = PolicyOutboundPfx
	}
	// To keep the number of rules low, we only drop a RETURN rule every
	// returnStride jump rules.
	const returnStride = 5
	for i, polName := range group.PolicyNames {
		if i != 0 && i%returnStride == 0 {
			// If policy makes a verdict (i.e. the pass or accept bit is
			// non-zero) return to the per-endpoint chain.  Note: the per-endpoint
			// chain has a similar rule that only checks the accept bit.  Pass
			// is handled differently in the per-endpoint chain because we need
			// to continue processing in the same chain on a pass rule.
			rules = append(rules, Rule{
				Match:   Match().Tagged(r.IpfwTagPass | r.IpfwTagAccept),
				Action:  ReturnAction{},
				Comment: []string{"Return on verdict"},
			})
		}

		var match MatchCriteria
		if i%returnStride == 0 {
			// Optimisation, we're the first rule in a block, immediately after
			// start of chain or a RETURN rule.  No need to check the return bits.
			match = Match()
		} else {
			// We're not the first rule in a block, only jump to this policy if
			// the previous policy didn't set a mark bit.
			match = Match().Tagged(r.IpfwTagPass | r.IpfwTagAccept)
		}

		chainToJumpTo := PolicyChainName(
			polChainPrefix,
			&proto.PolicyID{Name: polName},
		)
		rules = append(rules, Rule{
			Match:  match,
			Action: CallAction{Target: chainToJumpTo},
		})
	}
	return []*Chain{{
		Name:  group.ChainName(),
		Rules: rules,
	}}
}

func (r *DefaultRuleRenderer) endpointIpfwChain(policyGroups []*PolicyGroup, profileIds []string, name string, policyPrefix PolicyChainNamePrefix, profilePrefix ProfileChainNamePrefix, endpointPrefix string, failsafeChain string, chainType endpointChainType, adminUp bool, allowAction Action, allowVXLANEncap bool, allowIPIPEncap bool) *Chain {
	rules := []Rule{}
	chainName := EndpointChainName(endpointPrefix, name)

	if !adminUp {
		// Endpoint is admin-down, drop all traffic to/from it.
		rules = append(rules, Rule{
			Match:   Match(),
			Action:  r.IpfwFilterDenyAction(),
			Comment: []string{"Endpoint admin disabled"},
		})
		return &Chain{
			Name:  chainName,
			Rules: rules,
		}
	}

	if chainType != chainTypeUntracked {
		// Tracked chain: install conntrack rules, which implement our stateful connections.
		// This allows return traffic associated with a previously-permitted request.
		rules = r.appendConntrackRules(rules, allowAction)
	}

	// First set up failsafes.
	if failsafeChain != "" {
		rules = append(rules, Rule{
			Action: CallAction{Target: failsafeChain},
		})
	}

	// Start by ensuring that the policy result bits are clear.  Policy chains
	// set one of the bits to return their result (or leave the bits unset if
	// there's no match).
	rules = append(rules, Rule{
		Action: TagAction{
			TagNumber: r.IpfwTagAccept | r.IpfwTagPass,
		},
	})

	if len(policyGroups) > 0 {
		// Then, jump to each policy (or group) in turn.
		for _, polGroup := range policyGroups {
			var chainsToJumpTo []string
			if polGroup.ShouldBeInlined() {
				// Group is too small to have its own chain.
				for _, p := range polGroup.PolicyNames {
					chainsToJumpTo = append(chainsToJumpTo, PolicyChainName(
						policyPrefix,
						&proto.PolicyID{Name: p},
					))
				}
			} else {
				// Group needs its own chain.
				chainsToJumpTo = []string{polGroup.ChainName()}
			}

			for _, chainToJumpTo := range chainsToJumpTo {
				// If a previous policy/group didn't set the "pass" mark, jump to the policy.
				rules = append(rules, Rule{
					Match:  Match().Tagged(r.IpfwTagPass),
					Action: CallAction{Target: chainToJumpTo},
				})
				// If policy marked packet as accepted, it returns, setting the accept
				// mark bit.
				if chainType == chainTypeUntracked {
					// For an untracked policy, map allow to "NOTRACK and ALLOW".
					rules = append(rules, Rule{
						Match:  Match().Tagged(r.IpfwTagAccept),
						Action: CountAction{}, // NoTrackAction{}
					})
				}
				// If accept bit is set, return from this chain.  We don't immediately
				// accept because there may be other policy still to apply.
				rules = append(rules, Rule{
					Match:   Match().Tagged(r.IpfwTagAccept),
					Action:  ReturnAction{},
					Comment: []string{"Return if policy accepted"},
				})
			}
		}

		if chainType == chainTypeNormal || chainType == chainTypeForward {
			// When rendering normal and forward rules, if no policy marked the packet as "pass", drop
			// or reject the packet.
			//
			// For untracked and pre-DNAT rules, we don't do that because there may be
			// normal rules still to be applied to the packet in the filter table.
			rules = append(rules, Rule{
				Match:   Match().Tagged(r.IpfwTagPass),
				Action:  r.IpfwFilterDenyAction(),
				Comment: []string{fmt.Sprintf("%s if no policies passed packet", r.IpfwFilterDenyAction())},
			})
		}

	} else if chainType == chainTypeForward {
		// Forwarded traffic is allowed when there are no policies with
		// applyOnForward that apply to this endpoint (and in this direction).
		rules = append(rules, Rule{
			Action:  TagAction{TagNumber: r.IpfwTagAccept},
			Comment: []string{"Allow forwarded traffic by default"},
		})
		rules = append(rules, Rule{
			Action:  ReturnAction{},
			Comment: []string{"Return for accepted forward traffic"},
		})
	}

	if chainType == chainTypeNormal {
		// Then, jump to each profile in turn.
		for _, profileID := range profileIds {
			profChainName := ProfileChainName(profilePrefix, &proto.ProfileID{Name: profileID})
			rules = append(rules,
				Rule{Action: CallAction{Target: profChainName}},
				// If policy marked packet as accepted, it returns, setting the
				// accept mark bit.  If that is set, return from this chain.
				Rule{
					Match:   Match().Tagged(r.IpfwTagAccept),
					Action:  ReturnAction{},
					Comment: []string{"Return if profile accepted"},
				})
		}

		// When rendering normal rules, if no profile marked the packet as accepted, drop
		// the packet.
		//
		// For untracked rules, we don't do that because there may be tracked rules
		// still to be applied to the packet in the filter table.
		// if dropIfNoProfilesMatched {
		rules = append(rules, Rule{
			Match:   Match(),
			Action:  r.IpfwFilterDenyAction(),
			Comment: []string{fmt.Sprintf("%s if no profiles matched", r.IpfwFilterDenyAction())},
		})
		// }
	}

	return &Chain{
		Name:  chainName,
		Rules: rules,
	}
}

func (r *DefaultRuleRenderer) appendConntrackRules(rules []Rule, allowAction Action) []Rule {
	// Allow return packets for established connections.
	if allowAction != (AllowAction{}) {
		// If we've been asked to return instead of accept the packet immediately,
		// make sure we flag the packet as allowed.
		rules = append(rules,
			Rule{
				Match:  Match().ConntrackState("established"),
				Action: TagAction{TagNumber: r.IpfwTagAccept},
			},
		)
	}
	rules = append(rules,
		Rule{
			Match:  Match().ConntrackState("established"),
			Action: allowAction,
		},
	)
	if !r.Config.DisableConntrackInvalid {
		// Drop packets that aren't either a valid handshake or part of an established
		// connection.
		rules = append(rules, Rule{
			Match:  Match().ConntrackState("setup keep-state"),
			Action: r.IpfwFilterDenyAction(),
		})
	}
	return rules
}

func EndpointChainName(prefix string, ifaceName string) string {
	return hashutils.GetLengthLimitedID(
		prefix,
		ifaceName,
		MaxChainNameLength,
	)
}

// MaxPolicyGroupUIDLength is sized for UIDs to fit into their chain names.
const MaxPolicyGroupUIDLength = MaxChainNameLength - len(PolicyGroupInboundPrefix)

// PolicyGroup represents a sequence of one or more policies extracted from
// a list of policies.  If large enough (currently >1 entry) it will be
// programmed into its own chain.
type PolicyGroup struct {
	// Tier is only used in enterprise.  There can be policies with the same
	// name in different tiers so we need to disambiguate.
	Tier string
	// Direction matches the policy model direction inbound/outbound. Each
	// group is either inbound or outbound since the set of active policy
	// can differ between the directions (a policy may have inbound rules
	// only, for example).
	Direction   PolicyDirection
	PolicyNames []string
	// Selector is the original selector used by the grouped policies.  By
	// grouping on selector, we ensure that if one policy in a group matches
	// an endpoint then all policies in that group must match the endpoint.
	// Thus, two endpoint that share any policy in the group must share the
	// whole group.
	Selector string
	// cachedUID is the cached hash of the policy group details.  Filled in on
	// first call to UniqueID().
	cachedUID string
}

func (g *PolicyGroup) UniqueID() string {
	if g.cachedUID != "" {
		return g.cachedUID
	}

	hash := sha3.New224()
	write := func(s string) {
		_, err := hash.Write([]byte(s))
		if err != nil {
			log.WithError(err).Panic("Failed to write to hasher")
		}
		_, err = hash.Write([]byte("\n"))
		if err != nil {
			log.WithError(err).Panic("Failed to write to hasher")
		}
	}
	write(g.Tier)
	write(g.Selector)
	write(fmt.Sprint(g.Direction))
	write(strconv.Itoa(len(g.PolicyNames)))
	for _, name := range g.PolicyNames {
		write(name)
	}
	hashBytes := hash.Sum(make([]byte, 0, hash.Size()))
	g.cachedUID = base64.RawURLEncoding.EncodeToString(hashBytes)[:MaxPolicyGroupUIDLength]
	return g.cachedUID
}

func (g *PolicyGroup) ChainName() string {
	if g.Direction == PolicyDirectionInbound {
		return PolicyGroupInboundPrefix + g.UniqueID()
	}
	return PolicyGroupOutboundPrefix + g.UniqueID()
}

func (g *PolicyGroup) ShouldBeInlined() bool {
	return len(g.PolicyNames) <= 1
}

// PolicyGroupSliceStringer provides a String() method for a slice of
// PolicyGroup pointers.
type PolicyGroupSliceStringer []*PolicyGroup

func (p PolicyGroupSliceStringer) String() string {
	if p == nil {
		return "<nil>"
	}
	if len(p) == 0 {
		return "[]"
	}
	names := make([]string, len(p))
	for i, pg := range p {
		names[i] = pg.ChainName()
		if pg.ShouldBeInlined() {
			names[i] += "(inline)"
		}
	}
	return "[" + strings.Join(names, ",") + "]"
}
