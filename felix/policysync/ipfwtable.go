// Copyright (c) 2018 Tigera, Inc. All rights reserved.

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

//go:build freebsd

package policysync

import (
	"github.com/projectcalico/calico/felix/ipfwtable"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/set"

	log "github.com/sirupsen/logrus"
)

type ipfwTableInfo struct {
	ipfwtable.IpfwTableMetadata
	members set.Set[ipfwtable.IpfwTableMember]
}

func newIpfwTable(update *proto.IpfwTableUpdate) *ipfwTableInfo {
	s := &ipfwTableInfo{}

	switch update.GetType() {
	case proto.IpfwTableUpdate_IP:
		s.Type = ipfwtable.IpfwTableTypeHashIP
	case proto.IpfwTableUpdate_IP_AND_PORT:
		s.Type = ipfwtable.IpfwTableTypeHashIPPort
	case proto.IpfwTableUpdate_NET:
		s.Type = ipfwtable.IpfwTableTypeHashNet
	default:
		log.WithField("IpfwTableType", update.GetType()).Panic("unknown IpfwTableType")
	}

	s.SetID = update.GetId()

	// Note: We ignore MaxSize.

	s.replaceMembers(update)
	return s
}

func (s *ipfwTableInfo) replaceMembers(update *proto.IpfwTableUpdate) {
	s.members = set.New[ipfwtable.IpfwTableMember]()
	for _, ms := range update.GetMembers() {
		s.members.Add(s.Type.CanonicaliseMember(ms))
	}
}

func (s *ipfwTableInfo) deltaUpdate(update *proto.IpfwTableDeltaUpdate) {
	for _, ms := range update.GetAddedMembers() {
		s.members.Add(s.Type.CanonicaliseMember(ms))
	}
	for _, ms := range update.GetRemovedMembers() {
		s.members.Discard(s.Type.CanonicaliseMember(ms))
	}
}

func (s *ipfwTableInfo) getIpfwTableUpdate() *proto.IpfwTableUpdate {
	u := &proto.IpfwTableUpdate{Id: s.SetID, Type: s.getProtoType()}
	s.members.Iter(func(item ipfwtable.IpfwTableMember) error {
		u.Members = append(u.Members, item.String())
		return nil
	})
	return u
}

func (s *ipfwTableInfo) getProtoType() proto.IpfwTableUpdate_IpfwTableType {
	switch s.Type {
	case ipfwtable.IpfwTableTypeHashIP:
		return proto.IpfwTableUpdate_IP
	case ipfwtable.IpfwTableTypeHashIPPort:
		return proto.IpfwTableUpdate_IP_AND_PORT
	case ipfwtable.IpfwTableTypeHashNet:
		return proto.IpfwTableUpdate_NET
	default:
		log.WithField("IpfwTableType", s.Type).Panic("unknown IpfwTableType")
	}
	// Unhittable.
	return 0
}

type ruleList interface {
	GetInboundRules() []*proto.Rule
	GetOutboundRules() []*proto.Rule
}

func addIpfwTableRuleList(rl ruleList, s map[string]bool) {
	for _, rule := range rl.GetInboundRules() {
		AddIpfwTableRule(rule, s)
	}
	for _, rule := range rl.GetOutboundRules() {
		AddIpfwTableRule(rule, s)
	}
}

func AddIpfwTableRule(r *proto.Rule, s map[string]bool) {
	addAll(r.SrcIpfwTableIds, s)
	addAll(r.DstIpfwTableIds, s)
	addAll(r.DstIpPortSetIds, s)
	addAll(r.SrcNamedPortIpfwTableIds, s)
	addAll(r.DstNamedPortIpfwTableIds, s)
	addAll(r.NotSrcIpfwTableIds, s)
	addAll(r.NotDstIpfwTableIds, s)
	addAll(r.NotSrcNamedPortIpfwTableIds, s)
	addAll(r.NotDstNamedPortIpfwTableIds, s)
}

func addAll(items []string, s map[string]bool) {
	for _, i := range items {
		s[i] = true
	}
}
