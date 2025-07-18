// Copyright (c) 2018-2021 Tigera, Inc. All rights reserved.
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
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/ipfwtable"
	"github.com/projectcalico/calico/felix/dataplane/common"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

type hostIPManager struct {
	nonHostIfacesRegexp *regexp.Regexp
	hostIfaceToAddrs map[string]set.Set[string]

	hostIpfwTableID     string
	ipfwTableDataplane common.IpfwTableDataplane
	maxSize         int
}

func newHostIPManager(wlIfacesPrefixes []string,
	ipfwTableID string,
	ipfwtable common.IpfwTableDataplane,
	maxIpfwTableSize int) *hostIPManager {

	return newHostIPManagerWithShims(
		wlIfacesPrefixes,
		ipfwTableID,
		ipfwtable,
		maxIpfwTableSize,
	)
}

func newHostIPManagerWithShims(wlIfacesPrefixes []string,
	ipfwTableID string,
	ipfwtable common.IpfwTableDataplane,
	maxIpfwTableSize int) *hostIPManager {

	wlIfacesPattern := "^(" + strings.Join(wlIfacesPrefixes, "|") + ").*"
	wlIfacesRegexp := regexp.MustCompile(wlIfacesPattern)

	return &hostIPManager{
		nonHostIfacesRegexp: wlIfacesRegexp,
		hostIfaceToAddrs:    map[string]set.Set[string]{},
		hostIpfwTableID:         ipfwTableID,
		ipfwTableDataplane:     ipfwtable,
		maxSize:             maxIpfwTableSize,
	}
}

func (m *hostIPManager) getCurrentMembers() []string {
	members := []string{}
	for _, addrs := range m.hostIfaceToAddrs {
		addrs.Iter(func(ip string) error {
			members = append(members, ip)
			return nil
		})
	}

	return members
}

func (m *hostIPManager) OnUpdate(msg interface{}) {
	switch msg := msg.(type) {
	case *ifaceAddrsUpdate:
		log.WithField("update", msg).Info("Interface addrs changed.")
		if m.nonHostIfacesRegexp.MatchString(msg.Name) {
			log.WithField("update", msg).Debug("Not a real host interface, ignoring.")
			return
		}
		if msg.Addrs != nil {
			m.hostIfaceToAddrs[msg.Name] = msg.Addrs
		} else {
			delete(m.hostIfaceToAddrs, msg.Name)
		}

		metadata := ipfwtable.IpfwTableMetadata{
			Type:    ipfwtable.IpfwTableTypeIP,
			SetID:   m.hostIpfwTableID,
			MaxSize: m.maxSize,
		}
		m.ipfwTableDataplane.AddOrReplaceIpfwTable(metadata, m.getCurrentMembers())
	}
}

func (m *hostIPManager) CompleteDeferredWork() error {
	return nil
}
