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

package freebsd

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"syscall"
	"strconv"
	"strings"
	"regexp"
	"time"

	"purplekraken.com/pkg/gojail"
	"github.com/containernetworking/cni/pkg/skel"
	cniv1 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/oss-fun/plugins/pkg/ns"
	"github.com/sirupsen/logrus"
	"github.com/oss-fun/netlink"

	"github.com/projectcalico/calico/cni-plugin/pkg/types"
	api "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	calicoclient "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
)

const (
	SYSCALL_NETLINK_ROUTE = 0x0
)

type freebsdDataplane struct {
	allowIPForwarding bool
	mtu               int
	queues            int
	logger            *logrus.Entry
}

func NewFreeBSDDataplane(conf types.NetConf, logger *logrus.Entry) *freebsdDataplane {
	return &freebsdDataplane{
		allowIPForwarding: conf.ContainerSettings.AllowIPForwarding,
		mtu:               conf.MTU,
		queues:            conf.NumQueues,
		logger:            logger,
	}
}

func (d *freebsdDataplane) DoNetworking(
	ctx context.Context,
	calicoClient calicoclient.Interface,
	args *skel.CmdArgs,
	result *cniv1.Result,
	desiredVethName string,
	routes []*net.IPNet,
	endpoint *api.WorkloadEndpoint,
	annotations map[string]string,
) (hostVethName, contVethMAC string, err error) {
	hostVethName = desiredVethName
	contVethName := args.IfName
	var hasIPv4 bool

	d.logger.Infof("Setting the host side veth name to %s", hostVethName)

	hostNlHandle, err := netlink.NewHandle(SYSCALL_NETLINK_ROUTE)
	if err != nil {
		return "", "", fmt.Errorf("failed to create host netlink handle: %v", err)
	}

	defer hostNlHandle.Close()

	// Clean up if hostVeth exists.
	if oldHostVeth, err := hostNlHandle.LinkByName(hostVethName); err == nil {
		if err = hostNlHandle.LinkDel(oldHostVeth); err != nil {
			return "", "", fmt.Errorf("failed to delete old hostVeth %v: %v", hostVethName, err)
		}
		d.logger.Infof("Cleaning old hostVeth: %v", hostVethName)
	}

	la := netlink.NewLinkAttrs()
	la.Name = contVethName
	la.MTU = d.mtu
	la.NumTxQueues = d.queues
	la.NumRxQueues = d.queues
	epair := &netlink.Veth{
		LinkAttrs: la,
		PeerName: hostVethName,
	}

	if err = netlink.LinkAdd(epair); err != nil {
		d.logger.Errorf("Error adding epair %+v: %s", epair, err)
		return "", "", fmt.Errorf("Failed netlink.LinkAdd: %v", err)
	}

	jid, err := gojail.GetId(args.Netns)
	if err != nil {
		d.logger.Errorf("Error gojail.GetId: %v", err)
		return "", "", fmt.Errorf("Failed gojail.GetId: %v", err)
	}

	if err = netlink.LinkSetNsFd(epair, jid); err != nil {
		d.logger.Errorf("Error setting epair(%+v) in vnet: %s", epair, err)
		return "", "", fmt.Errorf("Failed netlink.LinkSetNsFd: %v", err)
	}

	hostVeth, err := hostNlHandle.LinkByName(hostVethName)
	if err != nil {
		return "", "", fmt.Errorf("failed to lookup %q: %v", hostVethName, err)
	}

	if mac, err := net.ParseMAC("EE:EE:EE:EE:EE:EE"); err != nil {
		d.logger.Infof("failed to parse MAC Address: %v. Using kernel generated MAC.", err)
	} else {
		// Set the MAC address on the host side interface so the kernel does not
		// have to generate a persistent address which fails some times.
		if err = hostNlHandle.LinkSetHardwareAddr(hostVeth, mac); err != nil {
			d.logger.Warnf("failed to Set MAC of %q: %v. Using kernel generated MAC.", hostVethName, err)
		}
	}

	// Figure out whether we have IPv4 addresses.
	for _, addr := range result.IPs {
		if addr.Address.IP.To4() != nil {
			hasIPv4 = true
			addr.Address.Mask = net.CIDRMask(31, 32)
		}
	}

	err = d.configureSysctls(hasIPv4)
	if err != nil {
		return "", "", fmt.Errorf("error configuring sysctls for interface: %s, error: %w", hostVethName, err)
	}

	// Explicitly set the veth to UP state; the veth won't get a link local address unless it's set to UP state.
	if err = hostNlHandle.LinkSetUp(hostVeth); err != nil {
		return "", "", fmt.Errorf("failed to set %q up: %w", hostVethName, err)
	}

	if err := exec.Command("jexec", strconv.Itoa(jid), "ifconfig", contVethName, "up").Run(); err != nil {
		return "", "", fmt.Errorf("failed to set %q up in jail: %w", contVethName, err)
	}

	if requestedContVethMac, found := annotations["cni.projectcalico.org/hwAddr"]; found {
		tmpContVethMAC, err := net.ParseMAC(requestedContVethMac)
		if err != nil {
			return "", "", fmt.Errorf("failed to parse MAC address %v provided via cni.projectcalico.org/hwAddr: %v",
				requestedContVethMac, err)
		}
		contVethMAC = tmpContVethMAC.String()
		err = exec.Command("jexec", strconv.Itoa(jid), "ifconfig", contVethName, "link", contVethMAC).Run()
		if err != nil {
			return "", "", fmt.Errorf("failed to set container veth MAC to %v as requested via cni.projectcalico.org/hwAddr: %v",
				requestedContVethMac, err)
		}
		d.logger.Infof("successfully configured container veth MAC to %v as requested via cni.projectcalico.org/hwAddr", contVethMAC)
	} else {
		out, err := exec.Command("jexec", strconv.Itoa(jid), "ifconfig", contVethName).Output()
		if err != nil {
			return "", "", fmt.Errorf("failed to run ifconfig: %w", err)
		}
		text := string(out)

		find := regexp.MustCompile(`(?i)ether\s+([0-9a-f:]{17})`)
		if match := find.FindStringSubmatch(text); match != nil {
			contVethMAC = strings.ToLower(match[1])
		}
	}

	d.logger.WithField("MAC", contVethMAC).Debug("Found MAC for container veth")


	for _, addr := range result.IPs {
		if err = exec.Command("jexec", strconv.Itoa(jid), "ifconfig", contVethName, "inet", addr.Address.String()).Run(); err != nil {
			return "", "", fmt.Errorf("failed to add IP addr to %v: %v", contVethName, err)
		}

		// addr.Addressの複製・反転
		hostAddr := net.IPNet {
			IP: flipLastBit(addr.Address.IP),
			Mask: addr.Address.Mask,
		}
		// hostVethにIP割当
		if err = netlink.AddrAdd(hostVeth, &netlink.Addr{IPNet: &hostAddr}); err != nil {
			return "", "", fmt.Errorf("failed to add IP addr to %q: %v", hostVeth, err)
		}

		// routeに追加
		err := exec.Command("jexec", strconv.Itoa(jid), "route", "add", "default", hostAddr.IP.String()).Run()
		if err != nil {
			return "", "", fmt.Errorf("failed to add route inside the container: %v", err)
		}
	}

	if err = d.configureContainerSysctls(hasIPv4); err != nil {
		return "", "", fmt.Errorf("error configuring sysctls for the container netns, error: %s", err)
	}

	if err != nil {
		d.logger.Errorf("Error creating veth: %s", err)
		return "", "", err
	}

	return hostVethName, contVethMAC, err
}

func flipLastBit(ip net.IP) net.IP {
	ip = ip.To4()
	if ip == nil {
		return nil // IPv6や無効なIPに対処
	}

	flipped := make(net.IP, len(ip))
	copy(flipped, ip)

	// 最後のバイトの最下位ビット (LSB) を反転
	flipped[3] ^= 1 // 0b00000001

	return flipped
}

func disableDAD(contVethName string) error {
	logrus.WithField("interface", contVethName).Info("Disabling DAD on interface.")
	dadSysctl := fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/accept_dad", contVethName)
	if err := writeProcSys(dadSysctl, "0"); err != nil {
		return fmt.Errorf("failed to disable DAD for %s: %w", contVethName, err)
	}
	return nil
}

// SetupRoutes sets up the routes for the host side of the veth pair.
func SetupRoutes(hostNlHandle *netlink.Handle, hostVeth netlink.Link, result *cniv1.Result) error {

	// Go through all the IPs and add routes for each IP in the result.
	for _, ipAddr := range result.IPs {
		route := netlink.Route{
			LinkIndex: hostVeth.Attrs().Index,
			Scope:     netlink.SCOPE_LINK,
			Dst:       &ipAddr.Address,
		}
		err := hostNlHandle.RouteAdd(&route)

		if err != nil {
			switch err {

			// Route already exists, but not necessarily pointing to the same interface.
			case syscall.EEXIST:
				// List all the routes for the interface.
				routes, err := hostNlHandle.RouteList(hostVeth, netlink.FAMILY_ALL)
				if err != nil {
					return fmt.Errorf("error listing routes")
				}

				// Go through all the routes pointing to the interface, and see if any of them is
				// exactly what we are intending to program.
				// If the route we want is already there then most likely it's programmed by Felix, so we ignore it,
				// and we return an error if none of the routes match the route we're trying to program.
				logrus.WithFields(logrus.Fields{"route": route, "scope": route.Scope}).Debug("Constructed route")
				for _, r := range routes {
					logrus.WithFields(logrus.Fields{"interface": hostVeth.Attrs().Name, "route": r, "scope": r.Scope}).Debug("Routes for the interface")
					if r.LinkIndex == route.LinkIndex && r.Dst.IP.Equal(route.Dst.IP) && r.Scope == route.Scope {
						// Route was already present on the host.
						logrus.WithFields(logrus.Fields{"interface": hostVeth.Attrs().Name}).Infof("CNI skipping add route. Route already exists")
						return nil
					}
				}

				// Search all routes and report the conflict, search the name of the iface
				routes, err = hostNlHandle.RouteList(nil, netlink.FAMILY_ALL)
				if err != nil {
					return fmt.Errorf("error listing routes")
				}

				var conflict string

				for _, r := range routes {
					if r.Dst != nil && r.Dst.IP.Equal(route.Dst.IP) {
						linkName := "unknown"
						if link, err := hostNlHandle.LinkByIndex(r.LinkIndex); err == nil {
							linkName = link.Attrs().Name
						}

						conflict = fmt.Sprintf("route (Ifindex: %d, Dst: %s, Scope: %v, Iface: %s)",
							r.LinkIndex, r.Dst.String(), r.Scope, linkName)
						break
					}
				}

				return fmt.Errorf("route (Ifindex: %d, Dst: %s, Scope: %v) already exists for an interface other than '%s': %s",
					route.LinkIndex, route.Dst.String(), route.Scope, hostVeth.Attrs().Name, conflict)
			default:
				return fmt.Errorf("failed to add route (Ifindex: %d, Dst: %s, Scope: %v, Iface: %s): %v",
					route.LinkIndex, route.Dst.String(), route.Scope, hostVeth.Attrs().Name, err)
			}
		}

		logrus.WithFields(logrus.Fields{"interface": hostVeth, "IP": ipAddr.Address}).Debugf("CNI adding route")
	}
	return nil
}

// configureSysctls configures necessary sysctls required for the host side of the veth pair for IPv4 and/or IPv6.
func (d *freebsdDataplane) configureSysctls(hasIPv4 bool) error {
	if hasIPv4 {
		// Enable IP forwarding of packets coming _from_ this interface.  For packets to
		// be forwarded in both directions we need this flag to be set on the fabric-facing
		// interface too (or for the global default to be set).
		cmd := exec.Command("sysctl", "-w", "net.inet.ip.forwarding=1")
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to set net.inet.ip.forwarding=1:output: %s, err: %s", output, err)
		}
	}

	return nil
}

// configureContainerSysctls configures necessary sysctls required inside the container netns.
func (d *freebsdDataplane) configureContainerSysctls(hasIPv4 bool) error {
	if hasIPv4 {
		if d.allowIPForwarding {
			d.logger.Info("Enabling IPv4 forwarding")
			cmd := exec.Command("sysctl", "-w", "net.inet.ip.forwarding=1")
			output, err := cmd.CombinedOutput()
			if err != nil {
				return fmt.Errorf("failed to set net.inet.ip.forwarding=1:output: %s, err: %s", output, err)
			}
		} else {
			d.logger.Info("Disabling IPv4 forwarding")
			cmd := exec.Command("sysctl", "-w", "net.inet.ip.forwarding=0")
			output, err := cmd.CombinedOutput()
			if err != nil {
				return fmt.Errorf("failed to set net.inet.ip.forwarding=0:output: %s, err: %s", output, err)
			}
		}
	}

	return nil
}

// writeProcSys takes the sysctl path and a string value to set i.e. "0" or "1" and sets the sysctl.
func writeProcSys(path, value string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	n, err := f.Write([]byte(value))
	if err == nil && n < len(value) {
		err = io.ErrShortWrite
	}
	if err1 := f.Close(); err == nil {
		err = err1
	}
	return err
}

func (d *freebsdDataplane) CleanUpNamespace(args *skel.CmdArgs) error {
	// Only try to delete the device if a namespace was passed in.
	logCtx := d.logger.WithFields(logrus.Fields{
		"netns": args.Netns,
		"iface": args.IfName,
	})
	if args.Netns == "" {
		logCtx.Info("CleanUpNamespace called with no netns name, ignoring.")
		return nil
	}

	logCtx.Info("Deleting workload's device in netns.")

	// We've seen veth deletion hang on some very old kernels so we do it from a background goroutine.
	startTime := time.Now()
	done := make(chan struct{})

	var nsErr, linkErr error

	go func() {
		defer close(done)
		nsErr = ns.WithNetNSPath(args.Netns, func(_ ns.NetNS) error {
			logCtx.Info("Entered netns, deleting veth.")
			ifName := args.IfName
			var iface netlink.Link
			iface, linkErr = netlink.LinkByName(ifName)
			if linkErr == nil {
				linkErr = netlink.LinkDel(iface)
			}

			// Always return nil so that we can tell the difference between an error from WithNetNSPath itself
			// and an error deleting the link.
			return nil
		})
	}()

	select {
	case <-done:
		if nsErr != nil {
			if _, ok := nsErr.(ns.NSPathNotExistErr); ok {
				logCtx.Info("Workload's netns already gone.  Nothing to do.")
				return nil
			}
			logCtx.WithError(nsErr).Error("Failed to enter workloads netns.")
			return fmt.Errorf("failed to enter netns: %w", nsErr)
		}

		if linkErr != nil {
			if _, ok := linkErr.(netlink.LinkNotFoundError); ok {
				logCtx.Info("Workload's veth was already gone.  Nothing to do.")
				return nil
			}
			logCtx.WithError(linkErr).Error("Failed to clean up workload's veth.")
			return fmt.Errorf("failed to clean up workload's veth inside netns: %w", linkErr)
		}

		logCtx.WithField("after", time.Since(startTime)).Infof("Deleted device in netns.")
	case <-time.After(20 * time.Second):
		return fmt.Errorf("timed out deleting device in netns %s", args.Netns)
	}

	return nil
}
