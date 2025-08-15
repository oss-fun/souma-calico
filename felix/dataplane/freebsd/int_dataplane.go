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

//go:build freebsd

package intdataplane

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	"github.com/oss-fun/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/felix/dataplane/common"
	"github.com/projectcalico/calico/felix/environment"
	"github.com/projectcalico/calico/felix/idalloc"
	"github.com/projectcalico/calico/felix/ifacemonitor"
	"github.com/projectcalico/calico/felix/ipfwtable"
	"github.com/projectcalico/calico/felix/ipfw"
	"github.com/projectcalico/calico/felix/ipfw/cmdshim"
	"github.com/projectcalico/calico/felix/jitter"
	"github.com/projectcalico/calico/felix/labelindex"
	"github.com/projectcalico/calico/felix/logutils"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/routerule"
	"github.com/projectcalico/calico/felix/routetable"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/felix/throttle"
	"github.com/projectcalico/calico/libcalico-go/lib/health"
	lclogutils "github.com/projectcalico/calico/libcalico-go/lib/logutils"
	cprometheus "github.com/projectcalico/calico/libcalico-go/lib/prometheus"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

const (
	// msgPeekLimit is the maximum number of messages we'll try to grab from our channels
	// before we apply the changes.  Higher values allow us to batch up more work on
	// the channel for greater throughput when we're under load (at cost of higher latency).
	msgPeekLimit = 100

	// Interface name used by kube-proxy to bind service ips.
	KubeIPVSInterface = "kube-ipvs0"

	// Route cleanup grace period. Used for workload routes only.
	routeCleanupGracePeriod = 10 * time.Second

	UNIX_RT_TABLE_MAIN = 0x0
)

var (
	countDataplaneSyncErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_int_dataplane_failures",
		Help: "Number of times dataplane updates failed and will be retried.",
	})
	countMessages = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "felix_int_dataplane_messages",
		Help: "Number dataplane messages by type.",
	}, []string{"type"})
	summaryApplyTime = cprometheus.NewSummary(prometheus.SummaryOpts{
		Name: "felix_int_dataplane_apply_time_seconds",
		Help: "Time in seconds that it took to apply a dataplane update.",
	})
	summaryBatchSize = cprometheus.NewSummary(prometheus.SummaryOpts{
		Name: "felix_int_dataplane_msg_batch_size",
		Help: "Number of messages processed in each batch. Higher values indicate we're " +
			"doing more batching to try to keep up.",
	})
	summaryIfaceBatchSize = cprometheus.NewSummary(prometheus.SummaryOpts{
		Name: "felix_int_dataplane_iface_msg_batch_size",
		Help: "Number of interface state messages processed in each batch. Higher " +
			"values indicate we're doing more batching to try to keep up.",
	})
	summaryAddrBatchSize = cprometheus.NewSummary(prometheus.SummaryOpts{
		Name: "felix_int_dataplane_addr_msg_batch_size",
		Help: "Number of interface address messages processed in each batch. Higher " +
			"values indicate we're doing more batching to try to keep up.",
	})

	processStartTime time.Time
	zeroKey          = wgtypes.Key{}

	maxCleanupRetries = 5
)

func init() {
	prometheus.MustRegister(countDataplaneSyncErrors)
	prometheus.MustRegister(summaryApplyTime)
	prometheus.MustRegister(countMessages)
	prometheus.MustRegister(summaryBatchSize)
	prometheus.MustRegister(summaryIfaceBatchSize)
	prometheus.MustRegister(summaryAddrBatchSize)
	processStartTime = time.Now()
}

type Config struct {
	Hostname             string
	NodeZone             string
	IPv6Enabled          bool
	RuleRendererOverride rules.RuleRenderer
	IPIPMTU              int
	VXLANMTU             int
	VXLANMTUV6           int
	VXLANPort            int

	MaxIpfwTableSize int

	RouteSyncDisabled            bool
	IpfwBackend                  string
	IpfwTableRefreshInterval        time.Duration
	RouteRefreshInterval         time.Duration
	DeviceRouteSourceAddress     net.IP
	DeviceRouteSourceAddressIPv6 net.IP
	DeviceRouteProtocol          netlink.RouteProtocol
	RemoveExternalRoutes         bool
	IpfwRefreshInterval          time.Duration
	IpfwPostWriteCheckInterval   time.Duration
	IpfwLockFilePath             string
	IpfwLockTimeout              time.Duration
	IpfwLockProbeInterval        time.Duration
	XDPRefreshInterval           time.Duration

	FloatingIPsEnabled bool

	NetlinkTimeout time.Duration

	RulesConfig rules.Config

	IfaceMonitorConfig ifacemonitor.Config

	StatusReportingInterval time.Duration

	ConfigChangedRestartCallback func()
	FatalErrorRestartCallback    func(error)

	PostInSyncCallback func()
	HealthAggregator   *health.HealthAggregator
	WatchdogTimeout    time.Duration
	RouteTableManager  *idalloc.IndexAllocator

	DebugSimulateDataplaneHangAfter  time.Duration
	DebugSimulateDataplaneApplyDelay time.Duration

	ExternalNodesCidrs []string

	SidecarAccelerationEnabled         bool
	ServiceLoopPrevention              string

	LookPathOverride func(file string) (string, error)

	FeatureDetectOverrides map[string]string
	FeatureGates           map[string]string

	// Populated with the smallest host MTU based on auto-detection.
	hostMTU         int
	MTUIfacePattern *regexp.Regexp

	RouteSource string

	KubernetesProvider config.Provider
}

type UpdateBatchResolver interface {
	// Opportunity for a manager component to resolve state that depends jointly on the updates
	// that it has seen since the preceding CompleteDeferredWork call.  Processing here can
	// include passing resolved state to other managers.  It should not include any actual
	// dataplane updates yet.  (Those should be actioned in CompleteDeferredWork.)
	ResolveUpdateBatch() error
}

// InternalDataplane implements an in-process Felix dataplane driver based on ipfw
// and ipfwtable.  It communicates with the datastore-facing part of Felix via the
// Send/RecvMessage methods, which operate on the protobuf-defined API objects.
//
// # Architecture
//
// The internal dataplane driver is organised around a main event loop, which handles
// update events from the datastore and dataplane.
//
// Each pass around the main loop has two phases.  In the first phase, updates are fanned
// out to "manager" objects, which calculate the changes that are needed and pass them to
// the dataplane programming layer.  In the second phase, the dataplane layer applies the
// updates in a consistent sequence.  The second phase is skipped until the datastore is
// in sync; this ensures that the first update to the dataplane applies a consistent
// snapshot.
//
// Having the dataplane layer batch updates has several advantages.  It is much more
// efficient to batch updates, since each call to ipfw/ipfwtable has a high fixed cost.
// In addition, it allows for different managers to make updates without having to
// coordinate on their sequencing.
//
// # Requirements on the API
//
// The internal dataplane does not do consistency checks on the incoming data (as the
// old Python-based driver used to do).  It expects to be told about dependent resources
// before they are needed and for their lifetime to exceed that of the resources that
// depend on them. For example, it is important that the datastore layer sends an IP set
// create event before it sends a rule that references that IP set.
type InternalDataplane struct {
	toDataplane             chan interface{}
	fromDataplane           chan interface{}
	sendDataplaneInSyncOnce sync.Once

	allIpfwRuleSet    []*ipfw.RuleSet
	ipfwTable          []common.IpfwTableDataplane

	ifaceMonitor *ifacemonitor.InterfaceMonitor
	ifaceUpdates chan any

	endpointStatusCombiner *endpointStatusCombiner

	allManagers             []Manager
	managersWithRouteTables []ManagerWithRouteTables
	managersWithRouteRules  []ManagerWithRouteRules
	ruleRenderer            rules.RuleRenderer

	// datastoreInSync is set to true after we receive the "in sync" message from the datastore.
	// We delay programming of the dataplane until we're in sync with the datastore.
	datastoreInSync bool
	// ifaceMonitorInSync is set to true after the interface monitor reports that it is in sync.
	// As above, we block dataplane updates until we get that message.
	ifaceMonitorInSync bool

	// dataplaneNeedsSync is set if the dataplane is dirty in some way, i.e. we need to
	// call apply().
	dataplaneNeedsSync bool
	// forceIpfwTableRefresh is set by the IP sets refresh timer to indicate that we should
	// check the IP sets in the dataplane.
	forceIpfwTableRefresh bool
	// forceRouteRefresh is set by the route refresh timer to indicate that we should
	// check the routes in the dataplane.
	forceRouteRefresh bool
	// forceXDPRefresh is set by the XDP refresh timer to indicate that we should
	// check the XDP state in the dataplane.
	forceXDPRefresh bool
	// doneFirstApply is set after we finish the first update to the dataplane. It indicates
	// that the dataplane should now be in sync, though it is possible that an error occurred
	// necessitating a re-apply.
	doneFirstApply bool

	reschedTimer *time.Timer
	reschedC     <-chan time.Time

	applyThrottle *throttle.Throttle

	config Config

	debugHangC <-chan time.Time

	callbacks         *common.Callbacks

	loopSummarizer *logutils.Summarizer

	// Fields used to accumulate counts of messages of various types before we report them to
	// prometheus.
	datastoreBatchSize   int
	linkUpdateBatchSize  int
	addrsUpdateBatchSize int
}

const (
	healthName     = "InternalDataplaneMainLoop"
	healthInterval = 10 * time.Second

	ipipMTUOverhead        = 20
	vxlanMTUOverhead       = 50
	vxlanV6MTUOverhead     = 70
	wireguardMTUOverhead   = 60
	wireguardV6MTUOverhead = 80
	aksMTUOverhead         = 100
)

func NewIntDataplaneDriver(config Config) *InternalDataplane {
	log.WithField("config", config).Info("Creating internal FreeBSD dataplane driver.")
	ruleRenderer := rules.NewRenderer(config.RulesConfig)

	epTagMapper := rules.NewEndpointTagMapper(config.RulesConfig.IpfwTagNonCaliEndpoint)

	// Auto-detect host MTU.
	hostMTU, err := findHostMTU(config.MTUIfacePattern)
	if err != nil {
		log.WithError(err).Fatal("Unable to detect host MTU, shutting down")
		return nil
	}
	ConfigureDefaultMTUs(hostMTU, &config)
	podMTU := determinePodMTU(config)
	if err := writeMTUFile(podMTU); err != nil {
		log.WithError(err).Error("Failed to write MTU file, pod MTU may not be properly set")
	}

	featureDetector := environment.NewFeatureDetector(
		config.FeatureDetectOverrides,
		environment.WithFeatureGates(config.FeatureGates),
	)
	dp := &InternalDataplane{
		toDataplane:    make(chan interface{}, msgPeekLimit),
		fromDataplane:  make(chan interface{}, 100),
		ruleRenderer:   ruleRenderer,
		ifaceMonitor:   ifacemonitor.New(config.IfaceMonitorConfig, featureDetector, config.FatalErrorRestartCallback),
		ifaceUpdates:   make(chan any, 100),
		config:         config,
		applyThrottle:  throttle.New(10),
		loopSummarizer: logutils.NewSummarizer("dataplane reconciliation loops"),
	}
	dp.applyThrottle.Refill() // Allow the first apply() immediately.
	dp.ifaceMonitor.StateCallback = dp.onIfaceStateChange
	dp.ifaceMonitor.AddrCallback = dp.onIfaceAddrsChange
	dp.ifaceMonitor.InSyncCallback = dp.onIfaceInSync

	backendMode := environment.DetectBackend(config.LookPathOverride, cmdshim.NewRealCmd, config.IpfwBackend)

	// Most ipfw tables need the same options.
	ipfwOptions := ipfw.RulesetOptions{
		HistoricChainPrefixes: rules.AllHistoricChainNamePrefixes,
		RefreshInterval:       config.IpfwRefreshInterval,
		PostWriteInterval:     config.IpfwPostWriteCheckInterval,
		LockTimeout:           config.IpfwLockTimeout,
		LockProbeInterval:     config.IpfwLockProbeInterval,
		BackendMode:           backendMode,
		OnStillAlive:          dp.reportHealth,
		OpRecorder:            dp.loopSummarizer,
	}

	var ipfwLock sync.Locker
	if config.IpfwLockTimeout <= 0 {
		log.Debug("Calico implementation of ipfw lock disabled (by configuration).")
		ipfwLock = dummyLock{}
	} else {
		log.WithField("timeout", config.IpfwLockTimeout).Debug(
			"Calico implementation of ipfw lock enabled")
		ipfwLock = ipfw.NewSharedLock(
			config.IpfwLockFilePath,
			config.IpfwLockTimeout,
			config.IpfwLockProbeInterval,
		)
	}

	allRulesetV4 := ipfw.NewRuleSet(
		"all",
		4,
		rules.RuleHashPrefix,
		ipfwLock,
		featureDetector,
		ipfwOptions)
	ipfwtableConfigV4 := config.RulesConfig.IpfwTableConfigV4
	ipfwTableV4 := ipfwtable.NewIpfwTable(ipfwtableConfigV4, dp.loopSummarizer)
	dp.allIpfwRuleSet = append(dp.allIpfwRuleSet, allRulesetV4)
	dp.ipfwTable = append(dp.ipfwTable, ipfwTableV4)

	dp.endpointStatusCombiner = newEndpointStatusCombiner(dp.fromDataplane, config.IPv6Enabled)

	callbacks := common.NewCallbacks()
	dp.callbacks = callbacks

	ipfwTableManager := common.NewIpfwTableManager("ipv4", ipfwTableV4, config.MaxIpfwTableSize)

	dp.RegisterManager(ipfwTableManager)

	dp.RegisterManager(newHostIPManager(
		config.RulesConfig.WorkloadIfacePrefixes,
		rules.IpfwTableIDThisHostIPs,
		ipfwTableV4,
		config.MaxIpfwTableSize))
	dp.RegisterManager(newPolicyManager(allRulesetV4, ruleRenderer, 4))

	interfaceRegexes := make([]string, len(config.RulesConfig.WorkloadIfacePrefixes))
	for i, r := range config.RulesConfig.WorkloadIfacePrefixes {
		interfaceRegexes[i] = "^" + r + ".*"
	}

	var routeTableV4 routetable.RouteTableInterface

	if !config.RouteSyncDisabled {
		log.Debug("RouteSyncDisabled is false.")
		routeTableV4 = routetable.New(interfaceRegexes, 4, config.NetlinkTimeout,
			config.DeviceRouteSourceAddress, config.DeviceRouteProtocol, config.RemoveExternalRoutes, UNIX_RT_TABLE_MAIN,
			dp.loopSummarizer, featureDetector, routetable.WithLivenessCB(dp.reportHealth),
			routetable.WithRouteCleanupGracePeriod(routeCleanupGracePeriod))
	} else {
		log.Info("RouteSyncDisabled is true, using DummyTable.")
		routeTableV4 = &routetable.DummyTable{}
	}

	epManager := newEndpointManager(
		allRulesetV4,
		ruleRenderer,
		routeTableV4,
		4,
		epTagMapper,
		false,
		config.RulesConfig.WorkloadIfacePrefixes,
		dp.endpointStatusCombiner.OnEndpointStatusUpdate,
		"",
		callbacks,
		config.FloatingIPsEnabled,
	)
	dp.RegisterManager(epManager)
	dp.RegisterManager(newFloatingIPManager(allRulesetV4, ruleRenderer, 4, config.FloatingIPsEnabled))
	dp.RegisterManager(newMasqManager(ipfwTableV4, allRulesetV4, ruleRenderer, config.MaxIpfwTableSize, 4))
	
	dp.RegisterManager(newServiceLoopManager(allRulesetV4, ruleRenderer, 4))

	// Register that we will report liveness and readiness.
	if config.HealthAggregator != nil {
		log.Info("Registering to report health.")
		timeout := config.WatchdogTimeout
		if timeout < healthInterval*2 {
			log.Warnf("Dataplane watchdog timeout (%v) too low, defaulting to %v", timeout, healthInterval*2)
			timeout = healthInterval * 2
		}
		config.HealthAggregator.RegisterReporter(
			healthName,
			&health.HealthReport{Live: true, Ready: true},
			timeout,
		)
	}

	if config.DebugSimulateDataplaneHangAfter != 0 {
		log.WithField("delay", config.DebugSimulateDataplaneHangAfter).Warn(
			"Simulating a dataplane hang.")
		dp.debugHangC = time.After(config.DebugSimulateDataplaneHangAfter)
	}

	return dp
}

// findHostMTU auto-detects the smallest host interface MTU.
func findHostMTU(matchRegex *regexp.Regexp) (int, error) {
	// Find all the interfaces on the host.
	links, err := netlink.LinkList()
	if err != nil {
		log.WithError(err).Error("Failed to list interfaces. Unable to auto-detect MTU")
		return 0, err
	}

	// Iterate through them, keeping track of the lowest MTU.
	smallest := 0
	for _, l := range links {
		// Skip links that we know are not external interfaces.
		fields := log.Fields{"mtu": l.Attrs().MTU, "name": l.Attrs().Name}
		if matchRegex == nil || !matchRegex.MatchString(l.Attrs().Name) {
			log.WithFields(fields).Debug("Skipping interface for MTU detection")
			continue
		}
		if !ifacemonitor.LinkIsOperUp(l) {
			log.WithFields(fields).Debug("Skipping down interface for MTU detection")
			continue
		}
		log.WithFields(fields).Debug("Examining link for MTU calculation")
		if l.Attrs().MTU < smallest || smallest == 0 {
			smallest = l.Attrs().MTU
		}
	}

	if smallest == 0 {
		// We failed to find a usable interface. Default the MTU of the host
		// to 1460 - the smallest among common cloud providers.
		log.Warn("Failed to auto-detect host MTU - no interfaces matched the MTU interface pattern. To use auto-MTU, set mtuIfacePattern to match your host's interfaces")
		return 1460, nil
	}
	return smallest, nil
}

// writeMTUFile writes the smallest MTU among enabled encapsulation types to disk
// for use by other components (e.g., CNI plugin).
func writeMTUFile(mtu int) error {
	// Make sure directory exists.
	if err := os.MkdirAll("/var/lib/calico", os.ModePerm); err != nil {
		return fmt.Errorf("failed to create directory /var/lib/calico: %s", err)
	}

	// Write the smallest MTU to disk so other components can rely on this calculation consistently.
	filename := "/var/lib/calico/mtu"
	log.Debugf("Writing %d to "+filename, mtu)
	if err := os.WriteFile(filename, []byte(fmt.Sprintf("%d", mtu)), 0644); err != nil {
		log.WithError(err).Error("Unable to write to " + filename)
		return err
	}
	return nil
}

// determinePodMTU looks at the configured MTUs and enabled encapsulations to determine which
// value for MTU should be used for pod interfaces.
func determinePodMTU(config Config) int {
	// Determine the smallest MTU among enabled encap methods. If none of the encap methods are
	// enabled, we'll just use the host's MTU.
	mtu := 0
	type mtuState struct {
		mtu     int
		enabled bool
	}
	for _, s := range []mtuState{
		{config.IPIPMTU, config.RulesConfig.IPIPEnabled},
		{config.VXLANMTU, config.RulesConfig.VXLANEnabled},
		{config.VXLANMTUV6, config.RulesConfig.VXLANEnabledV6},
	} {
		if s.enabled && s.mtu != 0 && (s.mtu < mtu || mtu == 0) {
			mtu = s.mtu
		}
	}

	if mtu == 0 {
		// No enabled encapsulation. Just use the host MTU.
		mtu = config.hostMTU
	} else if mtu > config.hostMTU {
		fields := logrus.Fields{"mtu": mtu, "hostMTU": config.hostMTU}
		log.WithFields(fields).Warn("Configured MTU is larger than detected host interface MTU")
	}
	log.WithField("mtu", mtu).Info("Determined pod MTU")
	return mtu
}

// ConfigureDefaultMTUs defaults any MTU configurations that have not been set.
// We default the values even if the encap is not enabled, in order to match behavior from earlier versions of Calico.
// However, they MTU will only be considered for allocation to pod interfaces if the encap is enabled.
func ConfigureDefaultMTUs(hostMTU int, c *Config) {
	c.hostMTU = hostMTU
	if c.IPIPMTU == 0 {
		log.Debug("Defaulting IPIP MTU based on host")
		c.IPIPMTU = hostMTU - ipipMTUOverhead
	}
	if c.VXLANMTU == 0 {
		log.Debug("Defaulting IPv4 VXLAN MTU based on host")
		c.VXLANMTU = hostMTU - vxlanMTUOverhead
	}
	if c.VXLANMTUV6 == 0 {
		log.Debug("Defaulting IPv6 VXLAN MTU based on host")
		c.VXLANMTUV6 = hostMTU - vxlanV6MTUOverhead
	}
}

func cleanUpIPIPAddrs() {
	// If IPIP is not enabled, check to see if there is are addresses in the IPIP device and delete them if there are.
	log.Debug("Checking if we need to clean up the IPIP device")

	var errFound bool

cleanupRetry:
	for i := 0; i <= maxCleanupRetries; i++ {
		errFound = false
		if i > 0 {
			log.Debugf("Retrying %v/%v times", i, maxCleanupRetries)
		}
		link, err := netlink.LinkByName("tunl0")
		if err != nil {
			if _, ok := err.(netlink.LinkNotFoundError); ok {
				log.Debug("IPIP disabled and no IPIP device found")
				return
			}
			log.WithError(err).Warn("IPIP disabled and failed to query IPIP device.")
			errFound = true

			// Sleep for 1 second before retrying
			time.Sleep(1 * time.Second)
			continue
		}
		addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
		if err != nil {
			log.WithError(err).Warn("IPIP disabled and failed to list addresses, will be unable to remove any old addresses from the device should they exist.")
			errFound = true

			// Sleep for 1 second before retrying
			time.Sleep(1 * time.Second)
			continue
		}

		for _, oldAddr := range addrs {
			if err := netlink.AddrDel(link, &oldAddr); err != nil {
				log.WithError(err).Errorf("IPIP disabled and failed to delete unwanted IPIP address %s.", oldAddr.IPNet)
				errFound = true

				// Sleep for 1 second before retrying
				time.Sleep(1 * time.Second)
				continue cleanupRetry
			}
		}
	}
	if errFound {
		log.Warnf("Giving up trying to clean up IPIP addresses after retrying %v times", maxCleanupRetries)
	}
}

func cleanUpVXLANDevice(deviceName string) {
	// If VXLAN is not enabled, check to see if there is a VXLAN device and delete it if there is.
	log.Debug("Checking if we need to clean up the VXLAN device")

	var errFound bool
	for i := 0; i <= maxCleanupRetries; i++ {
		errFound = false
		if i > 0 {
			log.Debugf("Retrying %v/%v times", i, maxCleanupRetries)
		}
		link, err := netlink.LinkByName(deviceName)
		if err != nil {
			if _, ok := err.(netlink.LinkNotFoundError); ok {
				log.Debug("VXLAN disabled and no VXLAN device found")
				return
			}
			log.WithError(err).Warn("VXLAN disabled and failed to query VXLAN device.")
			errFound = true

			// Sleep for 1 second before retrying
			time.Sleep(1 * time.Second)
			continue
		}
		if err = netlink.LinkDel(link); err != nil {
			log.WithError(err).Error("VXLAN disabled and failed to delete unwanted VXLAN device.")
			errFound = true

			// Sleep for 1 second before retrying
			time.Sleep(1 * time.Second)
			continue
		}
	}
	if errFound {
		log.Warnf("Giving up trying to clean up VXLAN device after retrying %v times", maxCleanupRetries)
	}
}

type Manager interface {
	// OnUpdate is called for each protobuf message from the datastore.  May either directly
	// send updates to the IpfwTable and ipfw.Table objects (which will queue the updates
	// until the main loop instructs them to act) or (for efficiency) may wait until
	// a call to CompleteDeferredWork() to flush updates to the dataplane.
	OnUpdate(protoBufMsg interface{})
	// Called before the main loop flushes updates to the dataplane to allow for batched
	// work to be completed.
	CompleteDeferredWork() error
}

type ManagerWithRouteTables interface {
	Manager
	GetRouteTableSyncers() []routetable.RouteTableSyncer
}

type ManagerWithRouteRules interface {
	Manager
	GetRouteRules() []routeRules
}

type routeRules interface {
	SetRule(rule *routerule.Rule)
	RemoveRule(rule *routerule.Rule)
	QueueResync()
	Apply() error
}

func (d *InternalDataplane) routeTableSyncers() []routetable.RouteTableSyncer {
	var rts []routetable.RouteTableSyncer
	for _, mrts := range d.managersWithRouteTables {
		rts = append(rts, mrts.GetRouteTableSyncers()...)
	}

	return rts
}

func (d *InternalDataplane) routeRules() []routeRules {
	var rrs []routeRules
	for _, mrrs := range d.managersWithRouteRules {
		rrs = append(rrs, mrrs.GetRouteRules()...)
	}

	return rrs
}

func (d *InternalDataplane) RegisterManager(mgr Manager) {
	tableMgr, ok := mgr.(ManagerWithRouteTables)
	if ok {
		// Used to log the whole manager out here but if we do that then we cause races if the manager has
		// other threads or locks.
		log.WithField("manager", reflect.TypeOf(mgr).Name()).Debug("registering ManagerWithRouteTables")
		d.managersWithRouteTables = append(d.managersWithRouteTables, tableMgr)
	}

	rulesMgr, ok := mgr.(ManagerWithRouteRules)
	if ok {
		log.WithField("manager", mgr).Debug("registering ManagerWithRouteRules")
		d.managersWithRouteRules = append(d.managersWithRouteRules, rulesMgr)
	}
	d.allManagers = append(d.allManagers, mgr)
}

func (d *InternalDataplane) Start() {
	// Do our start-of-day configuration.
	d.doStaticDataplaneConfig()

	// Then, start the worker threads.
	go d.loopUpdatingDataplane()
	go d.loopReportingStatus()
	go d.ifaceMonitor.MonitorInterfaces()
	go d.monitorHostMTU()
}

// onIfaceInSync is used as a callback from the interface monitor.  We use it to send a message back to
// the main goroutine via a channel.
func (d *InternalDataplane) onIfaceInSync() {
	d.ifaceUpdates <- &ifaceInSync{}
}

type ifaceInSync struct {
}

// onIfaceStateChange is our interface monitor callback.  It gets called from the monitor's thread.
func (d *InternalDataplane) onIfaceStateChange(ifaceName string, state ifacemonitor.State, ifIndex int) {
	log.WithFields(log.Fields{
		"ifaceName": ifaceName,
		"ifIndex":   ifIndex,
		"state":     state,
	}).Info("Linux interface state changed.")
	d.ifaceUpdates <- &ifaceStateUpdate{
		Name:  ifaceName,
		State: state,
		Index: ifIndex,
	}
}

type ifaceStateUpdate struct {
	Name  string
	State ifacemonitor.State
	Index int
}

func NewIfaceStateUpdate(name string, state ifacemonitor.State, index int) any {
	return &ifaceStateUpdate{
		Name:  name,
		State: state,
		Index: index,
	}
}

// Check if current felix ipvs config is correct when felix gets a kube-ipvs0 interface update.
// If KubeIPVSInterface is UP and felix ipvs support is disabled (kube-proxy switched from ipfw to ipvs mode),
// or if KubeIPVSInterface is DOWN and felix ipvs support is enabled (kube-proxy switched from ipvs to ipfw mode),
// restart felix to pick up correct ipvs support mode.
func (d *InternalDataplane) checkIPVSConfigOnStateUpdate(state ifacemonitor.State) {
}

// onIfaceAddrsChange is our interface address monitor callback.  It gets called
// from the monitor's thread.
func (d *InternalDataplane) onIfaceAddrsChange(ifaceName string, addrs set.Set[string]) {
	log.WithFields(log.Fields{
		"ifaceName": ifaceName,
		"addrs":     addrs,
	}).Info("Linux interface addrs changed.")
	d.ifaceUpdates <- &ifaceAddrsUpdate{
		Name:  ifaceName,
		Addrs: addrs,
	}
}

type ifaceAddrsUpdate struct {
	Name  string
	Addrs set.Set[string]
}

func NewIfaceAddrsUpdate(name string, ips ...string) any {
	return &ifaceAddrsUpdate{
		Name:  name,
		Addrs: set.FromArray[string](ips),
	}
}

func (d *InternalDataplane) SendMessage(msg interface{}) error {
	d.toDataplane <- msg
	return nil
}

func (d *InternalDataplane) RecvMessage() (interface{}, error) {
	return <-d.fromDataplane, nil
}

func (d *InternalDataplane) monitorHostMTU() {
	for {
		mtu, err := findHostMTU(d.config.MTUIfacePattern)
		if err != nil {
			log.WithError(err).Error("Error detecting host MTU")
		} else if d.config.hostMTU != mtu {
			// Since log writing is done a background thread, we set the force-flush flag on this log to ensure that
			// all the in-flight logs get written before we exit.
			log.WithFields(log.Fields{lclogutils.FieldForceFlush: true}).Info("Host MTU changed")
			d.config.ConfigChangedRestartCallback()
		}
		time.Sleep(30 * time.Second)
	}
}

// doStaticDataplaneConfig sets up the kernel and our static ipfw  chains.  Should be called
// once at start of day before starting the main loop.  The actual ipfw programming is deferred
// to the main loop.
func (d *InternalDataplane) doStaticDataplaneConfig() {
	fmt.Printf("souma-log: doStaticDataplaneConfig")

	// Check/configure global kernel parameters.
	d.configureKernel()

	d.setUpIpfwNormal()

	log.Info("IPIP disabled. Not starting tunnel update thread.")
}

func (d *InternalDataplane) setUpIpfwNormal() {
	for _, t := range d.allIpfwRuleSet {
		filterChains := d.ruleRenderer.StaticFilterTableChains(t.IPVersion)
		t.UpdateChains(filterChains)
		t.InsertOrAppendRules("FORWARD", []ipfw.Rule{{
			Action: ipfw.CallAction{Target: rules.ChainFilterForward},
		}})
		t.InsertOrAppendRules("INPUT", []ipfw.Rule{{
			Action: ipfw.CallAction{Target: rules.ChainFilterInput},
		}})
		t.InsertOrAppendRules("OUTPUT", []ipfw.Rule{{
			Action: ipfw.CallAction{Target: rules.ChainFilterOutput},
		}})

		// Include rules which should be appended to the filter table forward chain.
		t.AppendRules("FORWARD", d.ruleRenderer.StaticFilterForwardAppendRules())
	}
}

func stringToProtocol(protocol string) (labelindex.IpfwTablePortProtocol, error) {
	switch protocol {
	case "tcp":
		return labelindex.ProtocolTCP, nil
	case "udp":
		return labelindex.ProtocolUDP, nil
	case "sctp":
		return labelindex.ProtocolSCTP, nil
	}
	return labelindex.ProtocolNone, fmt.Errorf("unknown protocol %q", protocol)
}

func (d *InternalDataplane) loopUpdatingDataplane() {
	log.Info("Started internal ipfw dataplane driver loop")
	healthTicks := time.NewTicker(healthInterval).C
	d.reportHealth()

	// Retry any failed operations every 10s.
	retryTicker := time.NewTicker(10 * time.Second)

	// If configured, start tickers to refresh the IP sets and routing table entries.
	ipfwTableRefreshC := newRefreshTicker("IP sets", d.config.IpfwTableRefreshInterval)
	routeRefreshC := newRefreshTicker("routes", d.config.RouteRefreshInterval)

	// Implement a simple leaky bucket throttle to control how often we refresh the dataplane.
	// This makes sure that we tend to favour processing updates from the datastore if we're
	// under load.
	throttleC := jitter.NewTicker(100*time.Millisecond, 10*time.Millisecond).Channel()
	beingThrottled := false

	for {
		select {
		case msg := <-d.toDataplane:
			d.onDatastoreMessage(msg)
		case ifaceUpdate := <-d.ifaceUpdates:
			d.onIfaceMonitorMessage(ifaceUpdate)
		case <-ipfwTableRefreshC:
			log.Debug("Refreshing IP sets state")
			d.forceIpfwTableRefresh = true
			d.dataplaneNeedsSync = true
		case <-routeRefreshC:
			log.Debug("Refreshing routes")
			d.forceRouteRefresh = true
			d.dataplaneNeedsSync = true
		case <-d.reschedC:
			log.Debug("Reschedule kick received")
			d.dataplaneNeedsSync = true
			// nil out the channel to record that the timer is now inactive.
			d.reschedC = nil
		case <-throttleC:
			d.applyThrottle.Refill()
		case <-healthTicks:
			d.reportHealth()
		case <-retryTicker.C:
		case <-d.debugHangC:
			log.Warning("Debug hang simulation timer popped, hanging the dataplane!!")
			time.Sleep(1 * time.Hour)
			log.Panic("Woke up after 1 hour, something's probably wrong with the test.")
		}

		if d.datastoreInSync && d.ifaceMonitorInSync && d.dataplaneNeedsSync {
			// Dataplane is out-of-sync, check if we're throttled.
			if d.applyThrottle.Admit() {
				if beingThrottled && d.applyThrottle.WouldAdmit() {
					log.Info("Dataplane updates no longer throttled")
					beingThrottled = false
				}
				log.Debug("Applying dataplane updates")
				applyStart := time.Now()

				if d.config.DebugSimulateDataplaneApplyDelay > 0 {
					log.WithField("delay", d.config.DebugSimulateDataplaneApplyDelay).Debug("Simulating a dataplane-apply delay")
					time.Sleep(d.config.DebugSimulateDataplaneApplyDelay)
				}
				// Actually apply the changes to the dataplane.
				d.apply()

				// Record stats.
				applyTime := time.Since(applyStart)
				summaryApplyTime.Observe(applyTime.Seconds())

				if d.dataplaneNeedsSync {
					// Dataplane is still dirty, record an error.
					countDataplaneSyncErrors.Inc()
				} else {
					d.sendDataplaneInSyncOnce.Do(func() {
						d.fromDataplane <- &proto.DataplaneInSync{}
					})
				}

				d.loopSummarizer.EndOfIteration(applyTime)

				if !d.doneFirstApply {
					log.WithField(
						"secsSinceStart", time.Since(processStartTime).Seconds(),
					).Info("Completed first update to dataplane.")
					d.loopSummarizer.RecordOperation("first-update")
					d.doneFirstApply = true
					if d.config.PostInSyncCallback != nil {
						d.config.PostInSyncCallback()
					}
				}
				d.reportHealth()
			} else {
				if !beingThrottled {
					log.Info("Dataplane updates throttled")
					beingThrottled = true
				}
			}
		}
	}
}

func newRefreshTicker(name string, interval time.Duration) <-chan time.Time {
	if interval <= 0 {
		log.Infof("Refresh of %s on timer disabled", name)
		return nil
	}
	log.WithField("interval", interval).Infof("Will refresh %s on timer", name)
	refreshTicker := jitter.NewTicker(interval, interval/10)
	return refreshTicker.Channel()
}

// onDatastoreMessage is called when we get a message from the calculation graph
// it opportunistically processes a match of messages from its channel.
func (d *InternalDataplane) onDatastoreMessage(msg interface{}) {
	d.datastoreBatchSize = 1

	// Process the message we received, then opportunistically process any other
	// pending messages.  This helps to avoid doing two dataplane updates in quick
	// succession (and hence increasing latency) if we're _not_ being throttled.
	d.processMsgFromCalcGraph(msg)
	drainChan(d.toDataplane, d.processMsgFromCalcGraph)

	summaryBatchSize.Observe(float64(d.datastoreBatchSize))
}

func (d *InternalDataplane) processMsgFromCalcGraph(msg interface{}) {
	log.WithField("msg", proto.MsgStringer{Msg: msg}).Infof("Received %T update from calculation graph", msg)
	d.datastoreBatchSize++
	d.dataplaneNeedsSync = true
	d.recordMsgStat(msg)
	for _, mgr := range d.allManagers {
		mgr.OnUpdate(msg)
	}
	switch msg.(type) {
	case *proto.InSync:
		log.WithField("timeSinceStart", time.Since(processStartTime)).Info(
			"Datastore in sync, flushing the dataplane for the first time...")
		d.datastoreInSync = true
	}
}

// onIfaceMonitorMessage is called when we get a message from the interface monitor
// it opportunistically processes a match of messages from its channel.
func (d *InternalDataplane) onIfaceMonitorMessage(ifaceUpdate any) {
	// Separate stats for historic reasons: there use to be two channels.
	d.linkUpdateBatchSize = 0
	d.addrsUpdateBatchSize = 0

	// As for datastore messages, the interface monitor can send many messages in one go, so we
	// opportunistically process a batch even if we're not being throttled.
	d.processIfaceUpdate(ifaceUpdate)
	drainChan(d.ifaceUpdates, d.processIfaceUpdate)

	d.dataplaneNeedsSync = true
	if d.linkUpdateBatchSize > 0 {
		summaryIfaceBatchSize.Observe(float64(d.linkUpdateBatchSize))
	}
	if d.addrsUpdateBatchSize > 0 {
		summaryAddrBatchSize.Observe(float64(d.addrsUpdateBatchSize))
	}
}

func (d *InternalDataplane) processIfaceUpdate(ifaceUpdate any) {
	switch ifaceUpdateMsg := ifaceUpdate.(type) {
	case *ifaceStateUpdate:
		d.processIfaceStateUpdate(ifaceUpdateMsg)
	case *ifaceAddrsUpdate:
		d.processIfaceAddrsUpdate(ifaceUpdateMsg)
	case *ifaceInSync:
		d.processIfaceInSync()
	}
}

func (d *InternalDataplane) processIfaceInSync() {
	if d.ifaceMonitorInSync {
		return
	}
	log.Info("Interface monitor now in sync.")
	d.ifaceMonitorInSync = true
	d.dataplaneNeedsSync = true
}

func (d *InternalDataplane) processIfaceStateUpdate(ifaceUpdate *ifaceStateUpdate) {
	log.WithField("msg", ifaceUpdate).Info("Received interface update")
	d.dataplaneNeedsSync = true
	d.linkUpdateBatchSize++
	if ifaceUpdate.Name == KubeIPVSInterface {
		d.checkIPVSConfigOnStateUpdate(ifaceUpdate.State)
		return
	}

	for _, mgr := range d.allManagers {
		mgr.OnUpdate(ifaceUpdate)
	}


	for _, mgr := range d.managersWithRouteTables {
		for _, routeTable := range mgr.GetRouteTableSyncers() {
			routeTable.OnIfaceStateChanged(ifaceUpdate.Name, ifaceUpdate.State)
		}
	}
}

func (d *InternalDataplane) processIfaceAddrsUpdate(ifaceAddrsUpdate *ifaceAddrsUpdate) {
	log.WithField("msg", ifaceAddrsUpdate).Info("Received interface addresses update")
	d.dataplaneNeedsSync = true
	d.addrsUpdateBatchSize++
	for _, mgr := range d.allManagers {
		mgr.OnUpdate(ifaceAddrsUpdate)
	}
}

func drainChan[T any](c <-chan T, f func(T)) {
	for i := 0; i < msgPeekLimit; i++ {
		select {
		case v := <-c:
			f(v)
		default:
			return
		}
	}
}

func (d *InternalDataplane) configureKernel() {
	mp := newModProbe(moduleConntrackSCTP, newRealCmd)
	out, err := mp.Exec()
	log.WithError(err).WithField("output", out).Infof("attempted to modprobe %s", moduleConntrackSCTP)

	log.Info("Making sure IPv4 forwarding is enabled.")
	err = exec.Command("sysctl", "-w", "net.inet.ip.forwarding=1").Run()
	if err != nil {
		log.WithError(err).Error("Failed to set IPv4 forwarding sysctl")
	}
}

func (d *InternalDataplane) recordMsgStat(msg interface{}) {
	typeName := reflect.ValueOf(msg).Elem().Type().Name()
	countMessages.WithLabelValues(typeName).Inc()
}

func (d *InternalDataplane) apply() {
	// Update sequencing is important here because ipfw rules have dependencies on ipfwtable.
	// Creating a rule that references an unknown IP set fails, as does deleting an IP set that
	// is in use.

	// Unset the needs-sync flag, we'll set it again if something fails.
	d.dataplaneNeedsSync = false

	// First, give the managers a chance to resolve any state based on the preceding batch of
	// updates.  In some cases, e.g. EndpointManager, this can result in an update to another
	// manager (BPFEndpointManager.OnHEPUpdate) that must happen before either of those managers
	// begins its dataplane programming updates.
	for _, mgr := range d.allManagers {
		if handler, ok := mgr.(UpdateBatchResolver); ok {
			err := handler.ResolveUpdateBatch()
			if err != nil {
				log.WithField("manager", reflect.TypeOf(mgr).Name()).WithError(err).Debug(
					"couldn't resolve update batch for manager, will try again later")
				d.dataplaneNeedsSync = true
			}
			d.reportHealth()
		}
	}

	// Now allow managers to complete the dataplane programming updates that they need.
	for _, mgr := range d.allManagers {
		err := mgr.CompleteDeferredWork()
		if err != nil {
			log.WithField("manager", reflect.TypeOf(mgr).Name()).WithError(err).Debug(
				"couldn't complete deferred work for manager, will try again later")
			d.dataplaneNeedsSync = true
		}
		d.reportHealth()
	}
	d.reportHealth()

	if d.forceRouteRefresh {
		// Refresh timer popped.
		for _, r := range d.routeTableSyncers() {
			// Queue a resync on the next Apply().
			r.QueueResync()
		}
		for _, r := range d.routeRules() {
			// Queue a resync on the next Apply().
			r.QueueResync()
		}
		d.forceRouteRefresh = false
	}

	if d.forceIpfwTableRefresh {
		// Refresh timer popped.
		for _, r := range d.ipfwTable {
			// Queue a resync on the next Apply().
			r.QueueResync()
		}
		d.forceIpfwTableRefresh = false
	}

	// Next, create/update IP sets.  We defer deletions of IP sets until after we update
	// ipfw.
	var ipfwTableWG sync.WaitGroup
	for _, ipfwTable := range d.ipfwTable {
		ipfwTableWG.Add(1)
		go func(ipfwTable common.IpfwTableDataplane) {
			ipfwTable.ApplyUpdates()
			d.reportHealth()
			ipfwTableWG.Done()
		}(ipfwTable)
	}

	// Update the routing table in parallel with the other updates.  We'll wait for it to finish
	// before we return.
	var routesWG sync.WaitGroup
	for _, r := range d.routeTableSyncers() {
		routesWG.Add(1)
		go func(r routetable.RouteTableSyncer) {
			err := r.Apply()
			if err != nil {
				log.Warn("Failed to synchronize routing table, will retry...")
				d.dataplaneNeedsSync = true
			}
			d.reportHealth()
			routesWG.Done()
		}(r)
	}

	// Update the routing rules in parallel with the other updates.  We'll wait for it to finish
	// before we return.
	var rulesWG sync.WaitGroup
	for _, r := range d.routeRules() {
		rulesWG.Add(1)
		go func(r routeRules) {
			err := r.Apply()
			if err != nil {
				log.Warn("Failed to synchronize routing rules, will retry...")
				d.dataplaneNeedsSync = true
			}
			d.reportHealth()
			rulesWG.Done()
		}(r)
	}
	// Wait for the IP sets update to finish.  We can't update iptables until it has.
	ipfwTableWG.Wait()

	// Update iptables, this should sever any references to now-unused IP sets.
	var reschedDelayMutex sync.Mutex
	var reschedDelay time.Duration
	var ipfwWG sync.WaitGroup
	for _, t := range d.allIpfwRuleSet {
		ipfwWG.Add(1)
		go func(t *ipfw.RuleSet) {
			tableReschedAfter := t.Apply()

			reschedDelayMutex.Lock()
			defer reschedDelayMutex.Unlock()
			if tableReschedAfter != 0 && (reschedDelay == 0 || tableReschedAfter < reschedDelay) {
				reschedDelay = tableReschedAfter
			}
			d.reportHealth()
			ipfwWG.Done()
		}(t)
	}
	ipfwWG.Wait()

	// Now clean up any left-over IP sets.
	var ipfwTableNeedsReschedule atomic.Bool
	for _, ipfwTable := range d.ipfwTable {
		ipfwTableWG.Add(1)
		go func(s common.IpfwTableDataplane) {
			defer ipfwTableWG.Done()
			reschedule := s.ApplyDeletions()
			if reschedule {
				ipfwTableNeedsReschedule.Store(true)
			}
			d.reportHealth()
		}(ipfwTable)
	}
	ipfwTableWG.Wait()
	if ipfwTableNeedsReschedule.Load() {
		if reschedDelay == 0 || reschedDelay > 100*time.Millisecond {
			reschedDelay = 100 * time.Millisecond
		}
	}

	// Wait for the route updates to finish.
	routesWG.Wait()

	// Wait for the rule updates to finish.
	rulesWG.Wait()

	// And publish and status updates.
	d.endpointStatusCombiner.Apply()

	// Set up any needed rescheduling kick.
	if d.reschedC != nil {
		// We have an active rescheduling timer, stop it so we can restart it with a
		// different timeout below if it is still needed.
		// This snippet comes from the docs for Timer.Stop().
		if !d.reschedTimer.Stop() {
			// Timer had already popped, drain its channel.
			<-d.reschedC
		}
		// Nil out our copy of the channel to record that the timer is inactive.
		d.reschedC = nil
	}
	if reschedDelay != 0 {
		// We need to reschedule.
		log.WithField("delay", reschedDelay).Debug("Asked to reschedule.")
		if d.reschedTimer == nil {
			// First time, create the timer.
			d.reschedTimer = time.NewTimer(reschedDelay)
		} else {
			// Have an existing timer, reset it.
			d.reschedTimer.Reset(reschedDelay)
		}
		d.reschedC = d.reschedTimer.C
	}
}

func (d *InternalDataplane) loopReportingStatus() {
	log.Info("Started internal status report thread")
	if d.config.StatusReportingInterval <= 0 {
		log.Info("Process status reports disabled")
		return
	}
	// Wait before first report so that we don't check in if we're in a tight cyclic restart.
	time.Sleep(10 * time.Second)
	for {
		uptimeSecs := time.Since(processStartTime).Seconds()
		d.fromDataplane <- &proto.ProcessStatusUpdate{
			IsoTimestamp: time.Now().UTC().Format(time.RFC3339),
			Uptime:       uptimeSecs,
		}
		time.Sleep(d.config.StatusReportingInterval)
	}
}

// IpfwTable is a shim interface for ipfw.Table.
type IpfwRuleSet interface {
	UpdateChain(chain *ipfw.Chain)
	UpdateChains([]*ipfw.Chain)
	RemoveChains([]*ipfw.Chain)
	RemoveChainByName(name string)
}

func (d *InternalDataplane) reportHealth() {
	if d.config.HealthAggregator != nil {
		d.config.HealthAggregator.Report(
			healthName,
			&health.HealthReport{Live: true, Ready: d.doneFirstApply && d.ifaceMonitorInSync},
		)
	}
}

type dummyLock struct{}

func (d dummyLock) Lock() {
}

func (d dummyLock) Unlock() {
}

