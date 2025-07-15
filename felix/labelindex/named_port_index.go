// Copyright (c) 2016-2019,2021-2022 Tigera, Inc. All rights reserved.

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

package labelindex

import (
	"math"
	"reflect"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/labelindex/labelnamevalueindex"
	"github.com/projectcalico/calico/felix/labelindex/labelrestrictionindex"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"

	"github.com/projectcalico/calico/felix/dispatcher"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/selector"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

var (
	gaugeNumEndpoints = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "felix_label_index_num_endpoints",
		Help: "Total number of endpoints and similar objects in the index.",
	})

	counterVecSelectorEvals = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "felix_label_index_selector_evals",
		Help: "Total number of selector evaluations.",
	}, []string{"result"})
	counterSelectorEvalsTrue  = counterVecSelectorEvals.WithLabelValues("true")
	counterSelectorEvalsFalse = counterVecSelectorEvals.WithLabelValues("false")

	gaugeVecSelectors = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "felix_label_index_num_active_selectors",
		Help: "Total number of active selectors in the policy rule label index.",
	}, []string{"optimized"})
	gaugeSelectorsOpt    = gaugeVecSelectors.WithLabelValues("true")
	gaugeSelectorsNonOpt = gaugeVecSelectors.WithLabelValues("false")

	counterVecScanStrat = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "felix_label_index_strategy_evals",
		Help: "Total number of index scans broken down by scan strategy.",
	}, []string{"strategy"})
)

func init() {
	prometheus.MustRegister(
		gaugeNumEndpoints,
		counterVecSelectorEvals,
		gaugeVecSelectors,
		counterVecScanStrat,
	)
}

// endpointData holds the data that we need to know about a particular endpoint.
type endpointData struct {
	labels  map[string]string
	nets    []ip.CIDR
	ports   []model.EndpointPort
	parents []*npParentData

	cachedMatchingIpfwTableIDs set.Set[string] /* or, as an optimization, nil if there are none */
}

func (d *endpointData) AddMatchingIpfwTableID(id string) {
	if d.cachedMatchingIpfwTableIDs == nil {
		d.cachedMatchingIpfwTableIDs = set.New[string]()
	}
	d.cachedMatchingIpfwTableIDs.Add(id)
}

func (d *endpointData) RemoveMatchingIpfwTableID(id string) {
	if d.cachedMatchingIpfwTableIDs == nil {
		return
	}
	d.cachedMatchingIpfwTableIDs.Discard(id)
	if d.cachedMatchingIpfwTableIDs.Len() == 0 {
		d.cachedMatchingIpfwTableIDs = nil
	}
}

func (d *endpointData) HasParent(parent *npParentData) bool {
	for _, p := range d.parents {
		if p == parent {
			return true
		}
	}
	return false
}

func (d *endpointData) LookupNamedPorts(name string, proto IpfwTablePortProtocol) []uint16 {
	var matchingPorts []uint16
	for _, p := range d.ports {
		if p.Name == name && proto.MatchesModelProtocol(p.Protocol) {
			matchingPorts = append(matchingPorts, p.Port)
		}
	}
	return matchingPorts
}

type IpfwTablePortProtocol uint8

func (p IpfwTablePortProtocol) MatchesModelProtocol(protocol numorstring.Protocol) bool {
	if protocol.Type == numorstring.NumOrStringNum {
		if protocol.NumVal == 0 {
			// Special case: named ports default to TCP if protocol isn't specified.
			return p == ProtocolTCP
		}
		return protocol.NumVal == uint8(p)
	}
	switch p {
	case ProtocolTCP:
		return strings.ToLower(protocol.StrVal) == "tcp"
	case ProtocolUDP:
		return strings.ToLower(protocol.StrVal) == "udp"
	case ProtocolSCTP:
		return strings.ToLower(protocol.StrVal) == "sctp"
	}
	log.WithField("protocol", p).Panic("Unknown protocol")
	return false
}

func (p IpfwTablePortProtocol) String() string {
	switch p {
	case ProtocolTCP:
		return "tcp"
	case ProtocolUDP:
		return "udp"
	case ProtocolSCTP:
		return "sctp"
	case ProtocolNone:
		return "none"
	default:
		return "unknown"
	}
}

const (
	ProtocolNone IpfwTablePortProtocol = 0
	ProtocolTCP  IpfwTablePortProtocol = 6
	ProtocolUDP  IpfwTablePortProtocol = 17
	ProtocolSCTP IpfwTablePortProtocol = 132
)

type IpfwTableMember struct {
	CIDR       ip.CIDR
	Protocol   IpfwTablePortProtocol
	PortNumber uint16
}

type ipfwTableData struct {
	// The selector and named port that this IP set represents.  If the selector is nil then
	// this IP set represents an unfiltered named port.  If namedPortProtocol == ProtocolNone then
	// this IP set represents a selector only, with no named port component.
	selector          selector.Selector
	namedPortProtocol IpfwTablePortProtocol
	namedPort         string

	// memberToRefCount stores a reference count for each member in the IP set.  Reference counts
	// may be >1 if an IP address is shared by more than one endpoint.
	memberToRefCount map[IpfwTableMember]uint64
}

// Get implements the Labels interface for endpointData.  Combines the endpoint's own labels with
// those of its parents on the fly.  This reduces the number of allocations we need to do, and
// it's fast in the mainline case (where there are 0-1 parents).
func (d *endpointData) Get(labelName string) (value string, present bool) {
	if value, present = d.labels[labelName]; present {
		return
	}
	for _, parent := range d.parents {
		if value, present = parent.labels[labelName]; present {
			return
		}
	}
	return
}

func (d *endpointData) OwnLabels() map[string]string {
	return d.labels
}

func (d *endpointData) IterOwnAndParentLabels(f func(k, v string)) {
	seenKeys := set.New[string]()
	for k, v := range d.labels {
		f(k, v)
		seenKeys.Add(k)
	}

	for _, parent := range d.parents {
		for k, v := range parent.labels {
			if seenKeys.Contains(k) {
				// label is shadowed.
				continue
			}
			// Non-shadowed parent label. Emit.
			f(k, v)
			seenKeys.Add(k)
		}
	}
	seenKeys.Clear()
}

func (d *endpointData) Equals(other *endpointData) bool {
	if len(d.labels) != len(other.labels) {
		return false
	}
	if len(d.ports) != len(other.ports) {
		return false
	}
	if len(d.nets) != len(other.nets) {
		return false
	}
	if len(d.parents) != len(other.parents) {
		return false
	}

	for k, v := range d.labels {
		otherLabel, exists := other.labels[k]
		if !exists || otherLabel != v {
			return false
		}
	}
	for i, p := range d.ports {
		if other.ports[i] != p {
			return false
		}
	}
	for i, c := range d.nets {
		if other.nets[i] != c {
			return false
		}
	}
	for i, p := range d.parents {
		// Note: this is a pointer comparison; we know that pointers will be shared.
		if other.parents[i] != p {
			return false
		}
	}
	return true
}

// npParentData holds the data that we know about each parent (i.e. each security profile).  Since,
// profiles consist of multiple resources in our data-model, the labels fields may be nil
// if we have partial information.
type npParentData struct {
	id          string
	labels      map[string]string
	endpointIDs set.Set[any]
}

func (d *npParentData) OwnLabels() map[string]string {
	return d.labels
}

func (d *npParentData) DiscardEndpointID(id any) {
	if d.endpointIDs == nil {
		panic("discard of unknown ID")
	}
	d.endpointIDs.Discard(id)
	if d.endpointIDs.Len() == 0 {
		d.endpointIDs = nil
	}
}

func (d *npParentData) AddEndpointID(id any) {
	if d.endpointIDs == nil {
		d.endpointIDs = set.New[any]()
	}
	d.endpointIDs.Add(id)
}

func (d *npParentData) IterEndpointIDs(f func(id any) error) {
	if d.endpointIDs == nil {
		return
	}
	d.endpointIDs.Iter(f)
}

type NamedPortMatchCallback func(ipfwTableID string, member IpfwTableMember)

type SelectorAndNamedPortIndex struct {
	endpointKVIdx *labelnamevalueindex.LabelNameValueIndex[any /*endpoint IDs*/, *endpointData]

	parentKVIdx           *labelnamevalueindex.LabelNameValueIndex[string, *npParentData]
	ipfwTableDataByID         map[string]*ipfwTableData
	selectorCandidatesIdx *labelrestrictionindex.LabelRestrictionIndex[string]

	// Callback functions
	OnMemberAdded   NamedPortMatchCallback
	OnMemberRemoved NamedPortMatchCallback

	OnAlive        func()
	lastLiveReport time.Time
}

func NewSelectorAndNamedPortIndex() *SelectorAndNamedPortIndex {
	inheritIdx := SelectorAndNamedPortIndex{
		endpointKVIdx: labelnamevalueindex.New[any, *endpointData]("endpoints"),
		parentKVIdx:   labelnamevalueindex.New[string, *npParentData]("parents"),
		ipfwTableDataByID: map[string]*ipfwTableData{},
		selectorCandidatesIdx: labelrestrictionindex.New[string](
			labelrestrictionindex.WithGauges[string](
				gaugeSelectorsOpt,
				gaugeSelectorsNonOpt,
			)),

		// Callback functions
		OnMemberAdded:   func(ipfwTableID string, member IpfwTableMember) {},
		OnMemberRemoved: func(ipfwTableID string, member IpfwTableMember) {},
		OnAlive:         func() {},
	}
	return &inheritIdx
}

func (idx *SelectorAndNamedPortIndex) RegisterWith(allUpdDispatcher *dispatcher.Dispatcher) {
	allUpdDispatcher.Register(model.ResourceKey{}, idx.OnUpdate)
	allUpdDispatcher.Register(model.WorkloadEndpointKey{}, idx.OnUpdate)
	allUpdDispatcher.Register(model.HostEndpointKey{}, idx.OnUpdate)
	allUpdDispatcher.Register(model.NetworkSetKey{}, idx.OnUpdate)
}

// OnUpdate makes SelectorAndNamedPortIndex compatible with the Dispatcher.  It accepts
// updates for endpoints and profiles and passes them through to the Update/DeleteXXX methods.
func (idx *SelectorAndNamedPortIndex) OnUpdate(update api.Update) (_ bool) {
	switch key := update.Key.(type) {
	case model.WorkloadEndpointKey:
		if update.Value != nil {
			log.Debugf("Updating NamedPortIndex with endpoint %v", key)
			endpoint := update.Value.(*model.WorkloadEndpoint)
			profileIDs := endpoint.ProfileIDs
			idx.UpdateEndpointOrSet(
				key,
				endpoint.Labels,
				extractCIDRsFromWorkloadEndpoint(endpoint),
				endpoint.Ports,
				profileIDs)
		} else {
			log.Debugf("Deleting endpoint %v from NamedPortIndex", key)
			idx.DeleteEndpoint(key)
		}
	case model.HostEndpointKey:
		if update.Value != nil {
			// Figure out what's changed and update the cache.
			log.Debugf("Updating NamedPortIndex for host endpoint %v", key)
			endpoint := update.Value.(*model.HostEndpoint)
			profileIDs := endpoint.ProfileIDs
			idx.UpdateEndpointOrSet(
				key,
				endpoint.Labels,
				extractCIDRsFromHostEndpoint(endpoint),
				endpoint.Ports,
				profileIDs)
		} else {
			log.Debugf("Deleting host endpoint %v from NamedPortIndex", key)
			idx.DeleteEndpoint(key)
		}
	case model.NetworkSetKey:
		if update.Value != nil {
			// Figure out what's changed and update the cache.
			log.Debugf("Updating NamedPortIndex for network set %v", key)
			netSet := update.Value.(*model.NetworkSet)
			profileIDs := netSet.ProfileIDs
			idx.UpdateEndpointOrSet(
				key,
				netSet.Labels,
				extractCIDRsFromNetworkSet(netSet),
				nil,
				profileIDs)
		} else {
			log.Debugf("Deleting network set %v from NamedPortIndex", key)
			idx.DeleteEndpoint(key)
		}
	case model.ResourceKey:
		if key.Kind != v3.KindProfile {
			return
		}
		if update.Value != nil {
			labels := update.Value.(*v3.Profile).Spec.LabelsToApply
			log.Debugf("Updating NamedPortIndex for profile labels %v: %v", key, labels)
			idx.UpdateParentLabels(key.Name, labels)
		} else {
			log.Debugf("Removing profile labels %v from NamedPortIndex", key)
			idx.DeleteParentLabels(key.Name)
		}
	}
	return
}

// extractCIDRsFromHostEndpoint converts the expected IPs of the host endpoint into /32 and /128
// CIDRs.
func extractCIDRsFromHostEndpoint(endpoint *model.HostEndpoint) []ip.CIDR {
	v4Addrs := endpoint.ExpectedIPv4Addrs
	v6Addrs := endpoint.ExpectedIPv6Addrs
	combined := make([]ip.CIDR, 0, len(v4Addrs)+len(v6Addrs))
	for _, addr := range v4Addrs {
		combined = append(combined, ip.FromNetIP(addr.IP).AsCIDR())
	}
	for _, addr := range v6Addrs {
		combined = append(combined, ip.FromNetIP(addr.IP).AsCIDR())
	}
	return combined
}

// extractCIDRsFromWorkloadEndpoint converts the IPv[46]Nets fields of the WorkloadEndpoint into
// /32 and /128 CIDRs.  It ignores any prefix length (but our validation ensures those nets are
// /32s or /128s in any case).
func extractCIDRsFromWorkloadEndpoint(endpoint *model.WorkloadEndpoint) []ip.CIDR {
	v4Nets := endpoint.IPv4Nets
	v6Nets := endpoint.IPv6Nets
	combined := make([]ip.CIDR, 0, len(v4Nets)+len(v6Nets))
	for _, addr := range v4Nets {
		combined = append(combined, ip.CIDRFromNetIP(addr.IP))
	}
	for _, addr := range v6Nets {
		combined = append(combined, ip.CIDRFromNetIP(addr.IP))
	}
	return combined
}

// extractCIDRsFromNetworkSet converts the Nets field of the NetworkSet into an []ip.CIDR slice.
func extractCIDRsFromNetworkSet(netSet *model.NetworkSet) []ip.CIDR {
	a := netSet.Nets
	combined := make([]ip.CIDR, 0, len(a))
	for _, addr := range a {
		cidr := ip.CIDRFromCalicoNet(addr)
		if cidr.Prefix() == 0 {
			// Special case: the linux dataplane can't handle 0-length CIDRs, so we split it into
			// multiple CIDRs.  Note: if the /1s were also in the network set, the deduplication is
			// handled by reference counting in the ipfwTableData struct.
			log.Debug("Converting 0 length CIDR to pair of /1s")
			switch cidr.Version() {
			case 4:
				combined = append(combined,
					ip.MustParseCIDROrIP("0.0.0.0/1"),
					ip.MustParseCIDROrIP("128.0.0.0/1"),
				)
			case 6:
				combined = append(combined,
					ip.MustParseCIDROrIP("::/1"),
					ip.MustParseCIDROrIP("8000::/1"),
				)
			default:
				log.WithField("cidr", cidr).Panic("Unknown IP version")
			}
		} else {
			// Normal case, just append the single CIDR.
			combined = append(combined, cidr)
		}
	}
	return combined
}

var defaultLogCtx = log.WithField("fieldsSuppressedAtThisLogLevel", "true")

func (idx *SelectorAndNamedPortIndex) UpdateIpfwTable(ipfwTableID string, sel selector.Selector, namedPortProtocol IpfwTablePortProtocol, namedPort string) {
	logCxt := defaultLogCtx
	if log.IsLevelEnabled(log.DebugLevel) {
		logCxt = log.WithFields(log.Fields{
			"ipfwTableID":           ipfwTableID,
			"selector":          sel,
			"namedPort":         namedPort,
			"namedPortProtocol": namedPortProtocol,
		})
		logCxt.Debug("Updating IP set")
	}
	if sel == nil {
		log.WithField("id", ipfwTableID).Panic("Selector should not be nil")
	}

	// Check whether anything has actually changed before we do a scan.
	oldIpfwTableData := idx.ipfwTableDataByID[ipfwTableID]
	if oldIpfwTableData != nil {
		if oldIpfwTableData.selector.UniqueID() == sel.UniqueID() &&
			oldIpfwTableData.namedPortProtocol == namedPortProtocol &&
			oldIpfwTableData.namedPort == namedPort {
			// Spurious refresh of existing IP set.
			logCxt.Debug("Skipping unchanged IP set")
			return
		}
		// This case indicates a change to the selector or named port without a change to the ID,
		// which isn't currently possible in Felix, since the ID is formed by hashing the other
		// values.  For completeness, handle (inefficiently) by simulating a deletion.
		log.WithField("ipfwTableID", ipfwTableID).Warn("IP set selector or named port changed for existing ID.")
		for m := range oldIpfwTableData.memberToRefCount {
			// Emit deletion events for the members.  We don't need to do that
			// for the expected, non-test code path because it's handled
			// en-masse.
			idx.OnMemberRemoved(ipfwTableID, m)
		}
		idx.DeleteIpfwTable(ipfwTableID)
	}

	// If we get here, we have a new IP set, and we need to scan endpoints
	// against its selector.
	newIpfwTableData := &ipfwTableData{
		selector:          sel,
		namedPort:         namedPort,
		namedPortProtocol: namedPortProtocol,
		memberToRefCount:  map[IpfwTableMember]uint64{},
	}
	idx.ipfwTableDataByID[ipfwTableID] = newIpfwTableData
	idx.selectorCandidatesIdx.AddSelector(ipfwTableID, sel)

	idx.iterEndpointCandidates(ipfwTableID, func(epID any, epData *endpointData) {
		idx.maybeReportLive()

		if !sel.EvaluateLabels(epData) {
			// Endpoint doesn't match.
			counterSelectorEvalsFalse.Inc()
			return
		}
		counterSelectorEvalsTrue.Inc()
		contrib := idx.CalculateEndpointContribution(epData, newIpfwTableData)
		if len(contrib) == 0 {
			return
		}
		if log.GetLevel() >= log.DebugLevel {
			logCxt = logCxt.WithField("epID", epID)
			logCxt.Debug("Endpoint contributes to IP set")
		}
		epData.AddMatchingIpfwTableID(ipfwTableID)
		for _, member := range contrib {
			refCount := newIpfwTableData.memberToRefCount[member]
			if refCount == 0 {
				if log.GetLevel() >= log.DebugLevel {
					logCxt.WithField("member", member).Debug("New IP set member")
				}
				idx.OnMemberAdded(ipfwTableID, member)
			}
			newIpfwTableData.memberToRefCount[member] = refCount + 1
		}
	})
}

func (idx *SelectorAndNamedPortIndex) DeleteIpfwTable(setID string) {
	ipfwTableData := idx.ipfwTableDataByID[setID]

	if ipfwTableData == nil {
		log.WithField("id", setID).Warning("Delete of unknown IP set, ignoring")
		return
	} else {
		log.WithFields(log.Fields{
			"ipfwTableID":  setID,
			"selector": ipfwTableData.selector.String(),
		}).Info("Deleting IP set")
	}

	idx.iterEndpointCandidates(setID, func(epID any, epData *endpointData) {
		// Make sure we don't appear non-live if there are a lot of endpoints
		// to get through.  Note: we don't bother evaluating the selector
		// here since it's faster to just do the cleanup unconditionally.
		idx.maybeReportLive()
		epData.RemoveMatchingIpfwTableID(setID)
	})

	delete(idx.ipfwTableDataByID, setID)
	idx.selectorCandidatesIdx.DeleteSelector(setID)
}

func (idx *SelectorAndNamedPortIndex) UpdateEndpointOrSet(
	id any,
	labels map[string]string,
	nets []ip.CIDR,
	ports []model.EndpointPort,
	parentIDs []string,
) {
	if log.IsLevelEnabled(log.DebugLevel) {
		log.WithFields(log.Fields{
			"endpointOrSetID": id,
			"newLabels":       labels,
			"CIDRs":           nets,
			"ports":           ports,
			"parentIDs":       parentIDs,
		}).Debug("Updating endpoint/network set")
	}

	// Calculate the new endpoint data.
	newEndpointData := &endpointData{}
	if len(labels) > 0 {
		newEndpointData.labels = labels
	}
	if len(parentIDs) > 0 {
		parents := make([]*npParentData, len(parentIDs))
		for i, pID := range parentIDs {
			parents[i] = idx.getOrCreateParent(pID)
		}
		newEndpointData.parents = parents
	}
	if len(nets) > 0 {
		newEndpointData.nets = nets
	}
	if len(ports) > 0 {
		newEndpointData.ports = ports
	}

	// Get the old endpoint data, so we can compare it.
	oldEndpointData, _ := idx.endpointKVIdx.Get(id)
	var oldIpfwTableContributions map[string][]IpfwTableMember
	if oldEndpointData != nil {
		// Before we do the (potentially expensive) selector scan, check if there can possibly be a
		// change.
		if oldEndpointData.Equals(newEndpointData) {
			log.Debug("Endpoint update makes no changes, skipping.")
			return
		}

		// If we get here, something about the endpoint has changed.  Calculate the old endpoint's
		// contribution to the IP sets that it matched.
		oldIpfwTableContributions = idx.RecalcCachedContributions(oldEndpointData)
		// Must remove from the index and then re-add in case the labels
		// or parents have changed.
		idx.endpointKVIdx.Remove(id)
	}

	// Calculate and compare the contribution of the new endpoint to IP sets.  Emit events for
	// new contributions and then mop up deletions.
	idx.scanEndpointAgainstIpfwTable(newEndpointData, oldIpfwTableContributions)

	// Record the new endpoint data.
	idx.endpointKVIdx.Add(id, newEndpointData)

	newParentIDs := set.New[any]()
	for _, parent := range newEndpointData.parents {
		parent.AddEndpointID(id)
		newParentIDs.Add(parent.id)
	}
	if oldEndpointData != nil {
		for _, parent := range oldEndpointData.parents {
			if newParentIDs.Contains(parent.id) {
				continue
			}
			parent.DiscardEndpointID(id)
			idx.discardParentIfEmpty(parent.id)
		}
	}

	gaugeNumEndpoints.Set(float64(idx.endpointKVIdx.Len()))
}

func (idx *SelectorAndNamedPortIndex) scanEndpointAgainstIpfwTable(
	epData *endpointData,
	oldIpfwTableContributions map[string][]IpfwTableMember,
) {
	// Remove any previous match from the endpoint's cache.  We'll re-add it
	// below if the match is still correct.
	epData.cachedMatchingIpfwTableIDs = nil

	// Iterate over potential new matches and incref any members that
	// that produces.  (This may temporarily over count.)
	idx.selectorCandidatesIdx.IterPotentialMatches(epData, func(ipfwTableID string, _ selector.Selector) {
		// Make sure we don't appear non-live if there are a lot of IP sets to get through.
		idx.maybeReportLive()

		ipfwTableData := idx.ipfwTableDataByID[ipfwTableID]
		matches := ipfwTableData.selector.EvaluateLabels(epData)
		log.Debugf("Selector %s matches endpoint? %v", ipfwTableData.selector.String(), matches)
		if matches {
			// Record the match in the index.  This allows us to quickly recalculate the
			// contribution of this endpoint later.
			epData.AddMatchingIpfwTableID(ipfwTableID)

			// Incref all the new members.  If any of them go from 0 to 1 reference then we
			// know that they're new.  We'll temporarily double-count members that were already
			// present, then decref them below.
			//
			// This reference counting also allows us to tolerate duplicate members in the
			// input data.
			newIpfwTableContribution := idx.CalculateEndpointContribution(epData, ipfwTableData)
			for _, newMember := range newIpfwTableContribution {
				newRefCount := ipfwTableData.memberToRefCount[newMember] + 1
				if newRefCount == 1 {
					// New member in the IP set.
					idx.OnMemberAdded(ipfwTableID, newMember)
				}
				ipfwTableData.memberToRefCount[newMember] = newRefCount
			}
		}
	})

	// Decref all the old matches, emitting events if we drop to zero.
	for ipfwTableID, oldMembers := range oldIpfwTableContributions {
		// Decref all the old members.  If they hit 0 references, then the member has been
		// removed so we emit an event.
		ipfwTableData := idx.ipfwTableDataByID[ipfwTableID]
		for _, oldMember := range oldMembers {
			newRefCount := ipfwTableData.memberToRefCount[oldMember] - 1
			if newRefCount == 0 {
				// Member no longer in the IP set.  Emit event and clean up the old reference
				// count.
				idx.OnMemberRemoved(ipfwTableID, oldMember)
				delete(ipfwTableData.memberToRefCount, oldMember)
			} else {
				ipfwTableData.memberToRefCount[oldMember] = newRefCount
			}
		}
	}
}

func (idx *SelectorAndNamedPortIndex) DeleteEndpoint(id any) {
	log.Debug("SelectorAndNamedPortIndex deleting endpoint", id)
	oldEndpointData, ok := idx.endpointKVIdx.Get(id)
	if !ok {
		return
	}

	log.WithField("oldContrib", oldEndpointData.cachedMatchingIpfwTableIDs).Debug("Old matching IP sets")
	oldIpfwTableContributions := idx.RecalcCachedContributions(oldEndpointData)
	for ipfwTableID, contributions := range oldIpfwTableContributions {
		// Decref all the old members.  If they hit 0 references, then the member has been
		// removed so we emit an event.
		log.WithField("ipfwTableID", ipfwTableID).Debug("Removing endpoint from IP set")
		ipfwTableData := idx.ipfwTableDataByID[ipfwTableID]
		for _, oldMember := range contributions {
			newRefCount := ipfwTableData.memberToRefCount[oldMember] - 1
			if newRefCount == 0 {
				// Member no longer in the IP set.  Emit event and clean up the old reference
				// count.
				idx.OnMemberRemoved(ipfwTableID, oldMember)
				delete(ipfwTableData.memberToRefCount, oldMember)
			} else {
				ipfwTableData.memberToRefCount[oldMember] = newRefCount
			}
		}
	}

	// Record the new endpoint data.
	idx.endpointKVIdx.Remove(id)
	for _, parent := range oldEndpointData.parents {
		parent.DiscardEndpointID(id)
		idx.discardParentIfEmpty(parent.id)
	}
	gaugeNumEndpoints.Set(float64(idx.endpointKVIdx.Len()))
}

func (idx *SelectorAndNamedPortIndex) UpdateParentLabels(parentID string, labels map[string]string) {
	parentData := idx.getOrCreateParent(parentID)
	if reflect.DeepEqual(parentData.labels, labels) {
		log.WithField("parentID", parentID).Debug("Skipping no-op update to parent labels")
		return
	}
	// Must remove the parent from the index while we mutate its labels.
	idx.parentKVIdx.Remove(parentID)
	oldLabels := parentData.labels
	idx.updateParent(
		parentData,
		// Function to apply the update.
		func() {
			parentData.labels = labels
		},
		// Function to back out the update.
		func() {
			parentData.labels = oldLabels
		},
	)
	idx.parentKVIdx.Add(parentID, parentData)
}

func (idx *SelectorAndNamedPortIndex) updateParent(parentData *npParentData, applyUpdate, revertUpdate func()) {
	parentData.IterEndpointIDs(func(id interface{}) error {
		epData, _ := idx.endpointKVIdx.Get(id)
		// This endpoint matches this parent, calculate its old contribution.  (The revert function
		// is a no-op on the first loop but keeping it here, rather than at the bottom of the loop
		// makes it harder to accidentally skip it with a well-intentioned "continue".)
		revertUpdate()
		oldIpfwTableContributions := idx.RecalcCachedContributions(epData)

		// Apply the update to the parent while we calculate this endpoint's new contribution.
		applyUpdate()
		idx.scanEndpointAgainstIpfwTable(epData, oldIpfwTableContributions)

		return nil
	})

	// Defensive: make sure we leave the update applied to the parent.
	applyUpdate()
}

func (idx *SelectorAndNamedPortIndex) DeleteParentLabels(parentID string) {
	// Defer to the update function, which implements the endpoint scanning logic.
	log.Debugf("Deleting parent labels: %v", parentID)
	idx.UpdateParentLabels(parentID, nil)
	idx.discardParentIfEmpty(parentID)
}

// CalculateEndpointContribution calculates the given endpoint's contribution to the given IP set.
// If the IP set represents a named port then the returned members will have a named port component.
// Returns nil if the endpoint doesn't contribute to the IP set.
func (idx *SelectorAndNamedPortIndex) CalculateEndpointContribution(d *endpointData, ipfwTableData *ipfwTableData) (contrib []IpfwTableMember) {
	if ipfwTableData.namedPortProtocol != ProtocolNone {
		// This IP set represents a named port match, calculate the cross product of
		// matching named ports by IP address.
		portNumbers := d.LookupNamedPorts(ipfwTableData.namedPort, ipfwTableData.namedPortProtocol)
		for _, namedPort := range portNumbers {
			for _, addr := range d.nets {
				contrib = append(contrib, IpfwTableMember{
					CIDR:       addr,
					Protocol:   ipfwTableData.namedPortProtocol,
					PortNumber: namedPort,
				})
			}
		}
	} else {
		// Non-named port match, simply return the CIDRs.
		for _, addr := range d.nets {
			contrib = append(contrib, IpfwTableMember{
				CIDR: addr,
			})
		}
	}
	return
}

// RecalcCachedContributions uses the cached set of matching IP set IDs in the endpoint
// struct to quickly recalculate the endpoint's contribution to all IP sets.
func (idx *SelectorAndNamedPortIndex) RecalcCachedContributions(epData *endpointData) map[string][]IpfwTableMember {
	if epData.cachedMatchingIpfwTableIDs == nil {
		return nil
	}
	contrib := map[string][]IpfwTableMember{}
	epData.cachedMatchingIpfwTableIDs.Iter(func(ipfwTableID string) error {
		ipfwTableData := idx.ipfwTableDataByID[ipfwTableID]
		if ipfwTableData == nil {
			log.WithField("ipfwTableID", ipfwTableID).Panic("Endpoint cachedMatchingIpfwTableIDs refers to nonexistent IP set.")
		}
		contrib[ipfwTableID] = idx.CalculateEndpointContribution(epData, ipfwTableData)
		return nil
	})
	return contrib
}

func (idx *SelectorAndNamedPortIndex) getOrCreateParent(id string) *npParentData {
	parent, ok := idx.parentKVIdx.Get(id)
	if !ok {
		parent = &npParentData{
			id: id,
		}
		idx.parentKVIdx.Add(id, parent)
	}
	return parent
}

func (idx *SelectorAndNamedPortIndex) discardParentIfEmpty(id string) {
	parent, ok := idx.parentKVIdx.Get(id)
	if !ok {
		return
	}
	if parent.endpointIDs == nil && parent.labels == nil {
		idx.parentKVIdx.Remove(id)
	}
}

func (idx *SelectorAndNamedPortIndex) maybeReportLive() {
	// We report from some tight loops so rate limit our reports.
	if time.Since(idx.lastLiveReport) < 100*time.Millisecond {
		return
	}
	idx.OnAlive()
	idx.lastLiveReport = time.Now()
}

// iterEndpointCandidates iterates over the subset of endpoints that the
// index says _may_ match the given IP set's selector.  It may produce additional
// non-matching endpoints (or all endpoints if no optimization is available).
func (idx *SelectorAndNamedPortIndex) iterEndpointCandidates(ipfwtableID string, f func(epID any, epData *endpointData)) {
	sel := idx.ipfwTableDataByID[ipfwtableID].selector
	restrictions := sel.LabelRestrictions()
	log.Debugf("Selector %s restrictions: %v", sel.String(), restrictions)

	// Implementation: endpoint labels and parent labels are each indexed
	// separately.  We consult the endpoint and parent indexes for each
	// "label restriction" extracted from the selector and keep track of the
	// best available scan strategy for endpoints and parents.  Then, compare
	// the best endpoint strategy vs the best parent strategy.

	bestEPStrategy := idx.endpointKVIdx.FullScanStrategy()
	bestParentStrategy := labelnamevalueindex.ScanStrategy[string](nil)
	bestParentEndpointEstimate := math.MaxInt

	for k, r := range restrictions {
		epStrat := idx.endpointKVIdx.StrategyFor(k, r)
		parentStrat := idx.parentKVIdx.StrategyFor(k, r)
		epsToScan := epStrat.EstimatedItemsToScan()
		parentsToScan := parentStrat.EstimatedItemsToScan()

		if epsToScan > 0 && parentsToScan == 0 {
			// Label matches no parents, but it does match some endpoints.
			if epsToScan < bestEPStrategy.EstimatedItemsToScan() {
				bestEPStrategy = epStrat
				log.Debugf("New best endpoint strategy: %s (%d)", bestEPStrategy, bestEPStrategy.EstimatedItemsToScan())
			}
		} else if epsToScan == 0 && parentsToScan > 0 {
			// Label matches no endpoints but it does match some parents.
			// (e.g. a Kubernetes namespace selector).
			parentEstimate := idx.estimateParentEndpointScanCount(parentStrat)
			if bestParentStrategy == nil || parentEstimate < bestParentEndpointEstimate {
				log.Debugf("New best parent strategy: %s", parentStrat)
				bestParentStrategy = parentStrat
				bestParentEndpointEstimate = parentEstimate
			}
		} else if parentsToScan > 0 && epsToScan > 0 {
			// Label matches both endpoints and parents.  This is impossible in
			// Kubernetes but it may be possible in OpenStack (or something
			// home-grown using raw etcd data).  For now don't try to optimize.
			log.WithField("label", k).Debug(
				"Label applies to both endpoints and parents, cannot do optimised scan.")
		} else {
			// This restriction rules out both a match on parent and a match
			// on endpoint.
			log.Debugf("Label restriction on label %s rules out both parent and endpoint match.", k)
			return
		}
	}

	if bestEPStrategy.EstimatedItemsToScan() <= bestParentEndpointEstimate {
		log.Debugf("Selector %s using endpoint scan strategy: %s", sel.String(), bestEPStrategy.String())
		counterVecScanStrat.WithLabelValues("endpoint-" + bestEPStrategy.Name()).Inc()
		bestEPStrategy.Scan(func(id any) bool {
			ep, _ := idx.endpointKVIdx.Get(id)
			f(id, ep)
			return true
		})
	} else {
		log.Debugf("Selector %s using parent scan strategy: %s", sel.String(), bestParentStrategy.String())
		seenEPIDs := set.New[any]()
		counterVecScanStrat.WithLabelValues("parent-" + bestParentStrategy.Name()).Inc()
		bestParentStrategy.Scan(func(parentID string) bool {
			parent, _ := idx.parentKVIdx.Get(parentID)
			parent.IterEndpointIDs(func(id any) error {
				if seenEPIDs.Contains(id) {
					return nil
				}
				seenEPIDs.Add(id)
				ep, _ := idx.endpointKVIdx.Get(id)
				f(id, ep)
				return nil
			})
			return true
		})
	}
}

func (idx *SelectorAndNamedPortIndex) estimateParentEndpointScanCount(s labelnamevalueindex.ScanStrategy[string]) int {
	numScanned := 0
	total := 0
	const maxNumToScan = 10
	s.Scan(func(id string) bool {
		parent, _ := idx.parentKVIdx.Get(id)
		if parent.endpointIDs != nil {
			parentSize := parent.endpointIDs.Len()
			total += parentSize
		}
		numScanned++
		return numScanned < maxNumToScan
	})
	if numScanned <= maxNumToScan {
		// Exact answer.
		return total
	}
	return (total*s.EstimatedItemsToScan() + maxNumToScan - 1) / maxNumToScan
}
