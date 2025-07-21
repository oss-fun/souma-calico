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

package dataplane

import (
	"fmt"
	"net"
	"os/exec"
	"runtime/debug"
	"strings"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	log "github.com/sirupsen/logrus"
	"github.com/oss-fun/netlink"

	"github.com/projectcalico/calico/felix/ipfwtable"
	"github.com/projectcalico/calico/felix/config"
	extdataplane "github.com/projectcalico/calico/felix/dataplane/external"
	"github.com/projectcalico/calico/felix/dataplane/inactive"
	intdataplane "github.com/projectcalico/calico/felix/dataplane/freebsd"
	"github.com/projectcalico/calico/felix/ifacemonitor"
	"github.com/projectcalico/calico/felix/logutils"
	"github.com/projectcalico/calico/felix/tagnum"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/libcalico-go/lib/health"
)

func StartDataplaneDriver(configParams *config.Config,
	healthAggregator *health.HealthAggregator,
	configChangedRestartCallback func(),
	fatalErrorCallback func(error)) (DataplaneDriver, *exec.Cmd) {

	if !configParams.IsLeader() {
		// Return an inactive dataplane, since we're not the leader.
		log.Info("Not the leader, using an inactive dataplane")
		return &inactive.InactiveDataplane{}, nil
	}

	if configParams.UseInternalDataplaneDriver {
		log.Info("Using internal FreeBSD dataplane driver.")
		// If kube ipvs interface is present, enable ipvs support.  In BPF mode, we bypass kube-proxy so IPVS
		// is irrelevant.
		if configChangedRestartCallback == nil || fatalErrorCallback == nil {
			log.Panic("Starting dataplane with nil callback func.")
		}

		tagNumManager := tagnum.NewTagNumManager("felix-ipfw")

		// Allocate mark bits; only the accept, scratch-0 and Wireguard bits are used in BPF mode so we
		// avoid allocating the others to minimize the number of bits in use.

		// The accept bit is a long-lived bit used to communicate between chains.
		var tagAccept, tagPass, tagScratch0, tagScratch1, tagEndpointNonCaliEndpoint uint16
		tagAccept, _ = tagNumManager.NextTagNum()

		// The pass bit is used to communicate from a policy chain up to the endpoint chain.
		tagPass, _ = tagNumManager.NextTagNum()

		// Scratch bits are short-lived bits used for calculating multi-rule results.
		tagScratch0, _ = tagNumManager.NextTagNum()
		tagScratch1, _ = tagNumManager.NextTagNum()

		if tagAccept == 0 || tagScratch0 == 0 || tagPass == 0 || tagScratch1 == 0 {
			log.WithFields(log.Fields{
				"Name":     "felix-ipfw",
			}).Panic("Not enough mark bits available.")
		}

		// Mark bits for endpoint mark. Currently Felix takes the rest bits from mask available for use.
		tagEndpointMark, _ := tagNumManager.NextTagNum()
		log.WithFields(log.Fields{
			"acceptTag":          tagAccept,
			"passTag":            tagPass,
			"scratch0Tag":        tagScratch0,
			"scratch1Tag":        tagScratch1,
			"endpointTag":        tagEndpointMark,
			"endpointMarkNonCali": tagEndpointNonCaliEndpoint,
		}).Info("Calculated ipfw mark bits")

		// Extract node labels from the hosts such they could be referenced later
		// e.g. Topology Aware Hints.
		felixHostname := configParams.FelixHostname

		var felixNodeZone string

		dpConfig := intdataplane.Config{
			Hostname:           felixHostname,
			NodeZone:           felixNodeZone,
			FloatingIPsEnabled: strings.EqualFold(configParams.FloatingIPs, string(apiv3.FloatingIPsEnabled)),
			IfaceMonitorConfig: ifacemonitor.Config{
				InterfaceExcludes: configParams.InterfaceExclude,
				ResyncInterval:    configParams.InterfaceRefreshInterval,
				NetlinkTimeout:    configParams.NetlinkTimeoutSecs,
			},
			RulesConfig: rules.Config{
				WorkloadIfacePrefixes: configParams.InterfacePrefixes(),

				IpfwTableConfigV4: ipfwtable.NewIPVersionConfig(
					ipfwtable.IPFamilyV4,
					rules.IpfwTableNamePrefix,
					rules.AllHistoricIpfwTableNamePrefixes,
					rules.LegacyV4IpfwTableNames,
				),

				OpenStackSpecialCasesEnabled: configParams.OpenstackActive(),
				OpenStackMetadataIP:          net.ParseIP(configParams.MetadataAddr),
				OpenStackMetadataPort:        uint16(configParams.MetadataPort),

				IpfwTagAccept:          tagAccept,
				IpfwTagPass:            tagPass,
				IpfwTagScratch0:        tagScratch0,
				IpfwTagScratch1:        tagScratch1,
				IpfwTagEndpoint:        tagEndpointMark,
				IpfwTagNonCaliEndpoint: tagEndpointNonCaliEndpoint,

				VXLANEnabled:   configParams.Encapsulation.VXLANEnabled,
				VXLANEnabledV6: configParams.Encapsulation.VXLANEnabledV6,
				VXLANPort:      configParams.VXLANPort,
				VXLANVNI:       configParams.VXLANVNI,

				IPIPEnabled:            configParams.Encapsulation.IPIPEnabled,
				FelixConfigIPIPEnabled: configParams.IpInIpEnabled,
				IPIPTunnelAddress:      configParams.IpInIpTunnelAddr,
				VXLANTunnelAddress:     configParams.IPv4VXLANTunnelAddr,
				VXLANTunnelAddressV6:   configParams.IPv6VXLANTunnelAddr,

				AllowVXLANPacketsFromWorkloads: configParams.AllowVXLANPacketsFromWorkloads,
				AllowIPIPPacketsFromWorkloads:  configParams.AllowIPIPPacketsFromWorkloads,

				WireguardEnabled:            configParams.WireguardEnabled,
				WireguardEnabledV6:          configParams.WireguardEnabledV6,
				RouteSource:                 configParams.RouteSource,

				IpfwLogPrefix:         configParams.LogPrefix,
				EndpointToHostAction:      configParams.DefaultEndpointToHostAction,
				IpfwFilterAllowAction: configParams.IpfwFilterAllowAction,
				IpfwMangleAllowAction: configParams.IpfwMangleAllowAction,
				IpfwFilterDenyAction:  configParams.IpfwFilterDenyAction,

				FailsafeInboundHostPorts:  configParams.FailsafeInboundHostPorts,
				FailsafeOutboundHostPorts: configParams.FailsafeOutboundHostPorts,

				DisableConntrackInvalid: configParams.DisableConntrackInvalidCheck,

				NATPortRange:                       configParams.NATPortRange,
				IpfwNATOutgoingInterfaceFilter: configParams.IpfwNATOutgoingInterfaceFilter,
				NATOutgoingAddress:                 configParams.NATOutgoingAddress,
				BPFEnabled:                         configParams.BPFEnabled,
				ServiceLoopPrevention:              configParams.ServiceLoopPrevention,
			},
			IPIPMTU:                        configParams.IpInIpMtu,
			VXLANMTU:                       configParams.VXLANMTU,
			VXLANMTUV6:                     configParams.VXLANMTUV6,
			VXLANPort:                      configParams.VXLANPort,
			IpfwBackend:                configParams.IpfwBackend,
			IpfwRefreshInterval:        configParams.IpfwRefreshInterval,
			RouteSyncDisabled:              configParams.RouteSyncDisabled,
			RouteRefreshInterval:           configParams.RouteRefreshInterval,
			DeviceRouteSourceAddress:       configParams.DeviceRouteSourceAddress,
			DeviceRouteSourceAddressIPv6:   configParams.DeviceRouteSourceAddressIPv6,
			DeviceRouteProtocol:            netlink.RouteProtocol(configParams.DeviceRouteProtocol),
			RemoveExternalRoutes:           configParams.RemoveExternalRoutes,
			IpfwTableRefreshInterval:          configParams.IpfwTableRefreshInterval,
			IpfwPostWriteCheckInterval: configParams.IpfwPostWriteCheckIntervalSecs,
			IpfwLockFilePath:           configParams.IpfwLockFilePath,
			IpfwLockTimeout:            configParams.IpfwLockTimeoutSecs,
			IpfwLockProbeInterval:      configParams.IpfwLockProbeIntervalMillis,
			MaxIpfwTableSize:                   configParams.MaxIpfwTableSize,
			IPv6Enabled:                    configParams.Ipv6Support,
			StatusReportingInterval:        configParams.ReportingIntervalSecs,
			XDPRefreshInterval:             configParams.XDPRefreshInterval,

			NetlinkTimeout: configParams.NetlinkTimeoutSecs,

			ConfigChangedRestartCallback: configChangedRestartCallback,
			FatalErrorRestartCallback:    fatalErrorCallback,

			PostInSyncCallback: func() {
				// The initial resync uses a lot of scratch space so now is
				// a good time to force a GC and return any RAM that we can.
				debug.FreeOSMemory()

				if configParams.DebugMemoryProfilePath == "" {
					return
				}
				logutils.DumpHeapMemoryProfile(configParams.DebugMemoryProfilePath)
			},
			HealthAggregator:                   healthAggregator,
			WatchdogTimeout:                    configParams.DataplaneWatchdogTimeout,
			DebugSimulateDataplaneHangAfter:    configParams.DebugSimulateDataplaneHangAfter,
			DebugSimulateDataplaneApplyDelay:   configParams.DebugSimulateDataplaneApplyDelay,
			ExternalNodesCidrs:                 configParams.ExternalNodesCIDRList,
			SidecarAccelerationEnabled:         configParams.SidecarAccelerationEnabled,

			FeatureDetectOverrides: configParams.FeatureDetectOverride,
			FeatureGates:           configParams.FeatureGates,

			RouteSource: configParams.RouteSource,
		}

		intDP := intdataplane.NewIntDataplaneDriver(dpConfig)
		intDP.Start()

		return intDP, nil
	} else {
		log.WithField("driver", configParams.DataplaneDriver).Info(
			"Using external dataplane driver.")

		return extdataplane.StartExtDataplaneDriver(configParams.DataplaneDriver)
	}
}

func SupportsBPF() error {
	return fmt.Errorf("BPF dataplane is not supported on FreeBSD")
}

func ConfigurePrometheusMetrics(configParams *config.Config) {
	if configParams.PrometheusGoMetricsEnabled && configParams.PrometheusProcessMetricsEnabled && configParams.PrometheusWireGuardMetricsEnabled {
		log.Info("Including Golang, Process and WireGuard metrics")
	} else {
		if !configParams.PrometheusGoMetricsEnabled {
			log.Info("Discarding Golang metrics")
			prometheus.Unregister(collectors.NewGoCollector())
		}
		if !configParams.PrometheusProcessMetricsEnabled {
			log.Info("Discarding process metrics")
			prometheus.Unregister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
		}
	}
}
