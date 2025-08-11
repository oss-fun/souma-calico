// Copyright (c) 2017,2020-2021 Tigera, Inc. All rights reserved.
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

package ifacemonitor

import (
	"fmt"
	"time"
	"net"

	log "github.com/sirupsen/logrus"
	"github.com/oss-fun/netlink"

	"github.com/projectcalico/calico/felix/environment"
	"github.com/projectcalico/calico/felix/netlinkshim/handlemgr"
)

const (
	UNIX_RT_TABLE_LOCAL = 0xff // FreeBSD not supported...
	UNIX_RTN_LOCAL      = 0x2
)

type netlinkReal struct {
	handleMgr *handlemgr.HandleManager
}

func newRealNetlink(featureDetector environment.FeatureDetectorIface, timeout time.Duration) *netlinkReal {
	return &netlinkReal{
		handleMgr: handlemgr.NewHandleManager(featureDetector, handlemgr.WithSocketTimeout(timeout)),
	}
}

func (nl *netlinkReal) Subscribe(
	linkUpdates chan netlink.LinkUpdate,
	routeUpdates chan netlink.RouteUpdate,
) (chan struct{}, error) {
	// Note: this method doesn't use the HandleManager because each subscription gets its own
	// socket under the covers.
	cancel := make(chan struct{})

	if err := netlink.LinkSubscribeWithOptions(linkUpdates, cancel, netlink.LinkSubscribeOptions{
		ErrorCallback: func(err error) {
			// Not necessarily fatal (can be an unexpected message, which the library will drop).
			log.WithError(err).Warn("Netlink reported an error.")
		},
	}); err != nil {
		log.WithError(err).Error("Failed to subscribe to link updates")
		close(cancel)
		return nil, err
	}
	if err := netlink.RouteSubscribeWithOptions(routeUpdates, cancel, netlink.RouteSubscribeOptions{
		ErrorCallback: func(err error) {
			// Not necessarily fatal (can be an unexpected message, which the library will drop).
			log.WithError(err).Warn("Netlink reported an error.")
		},
	}); err != nil {
		log.WithError(err).Error("Failed to subscribe to route updates")
		close(cancel)
		return nil, err
	}

	return cancel, nil
}

func (nl *netlinkReal) LinkList() ([]netlink.Link, error) {
	h, err := nl.handleMgr.Handle()
	if err != nil {
		return nil, fmt.Errorf("failed to get netlink handle: %w", err)
	}
	return h.LinkList()
}

func (nl *netlinkReal) ListLocalRoutes(link netlink.Link, family int) ([]netlink.Route, error) {
	var ifaces []net.Interface
	var err error

	if link != nil {
		// インターフェースが指定されている場合
		iface, err := net.InterfaceByIndex(link.Attrs().Index)
		if err != nil {
			return nil, fmt.Errorf("failed to get interface: %w", err)
		}
		ifaces = []net.Interface{*iface}
	} else {
		// 全インターフェース
		ifaces, err = net.Interfaces()
		if err != nil {
			return nil, fmt.Errorf("failed to list interfaces: %w", err)
		}
	}

	var routes []netlink.Route

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, fmt.Errorf("failed to list addresses for %s: %w", iface.Name, err)
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			// family フィルタ
			if family == netlink.FAMILY_V4 && ipNet.IP.To4() == nil {
				continue
			}
			if family == netlink.FAMILY_V6 && ipNet.IP.To4() != nil {
				continue
			}

			// Linux の RTN_LOCAL 相当のルートを netlink.Route 型で構築
			route := netlink.Route{
				LinkIndex: iface.Index,
				Scope:     netlink.SCOPE_HOST, // local は host scope
				Dst:       &net.IPNet{IP: ipNet.IP, Mask: ipNet.Mask},
				// Gw は nil（directly connected local addr）
				Table: UNIX_RT_TABLE_LOCAL,
				Type:  UNIX_RTN_LOCAL,
			}
			routes = append(routes, route)
		}
	}

	return routes, nil
}
