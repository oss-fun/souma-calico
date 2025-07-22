// Copyright (c) 2018-2022 Tigera, Inc. All rights reserved.
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

package environment

import (
	"bytes"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/netlinkshim"

	"github.com/projectcalico/calico/felix/ipfw/cmdshim"
)

var (
	vXDotYDotZRegexp = regexp.MustCompile(`v(\d+\.\d+\.\d+)`)
)

type FeatureDetector struct {
	featureDetectorCommon

	lock            sync.Mutex
	featureCache    *Features
	featureOverride map[string]string
	loggedOverrides bool

	// Path to file with kernel version
	GetKernelVersionReader func() (io.Reader, error)
	// Factory for making commands, used by iptables UTs to shim exec.Command().
	NewCmd cmdshim.CmdFactory

	newNetlinkHandle            func() (netlinkshim.Interface, error)
	cachedNetlinkSupportsStrict *bool
}

type Option func(detector *FeatureDetector)

func WithNetlinkOverride(f func() (netlinkshim.Interface, error)) Option {
	return func(detector *FeatureDetector) {
		detector.newNetlinkHandle = f
	}
}

func NewFeatureDetector(overrides map[string]string, opts ...Option) *FeatureDetector {
	fd := &FeatureDetector{
		GetKernelVersionReader: GetKernelVersionReader,
		NewCmd:                 cmdshim.NewRealCmd,
		featureOverride:        overrides,
		newNetlinkHandle:       netlinkshim.NewRealNetlink,
	}
	for _, opt := range opts {
		opt(fd)
	}
	return fd
}

func (d *FeatureDetector) GetFeatures() *Features {
	d.lock.Lock()
	defer d.lock.Unlock()

	if d.featureCache == nil {
		d.refreshFeaturesLockHeld()
	}

	return d.featureCache
}

func (d *FeatureDetector) RefreshFeatures() {
	d.lock.Lock()
	defer d.lock.Unlock()

	d.refreshFeaturesLockHeld()
}

func (d *FeatureDetector) refreshFeaturesLockHeld() {
	d.featureCache = &Features {
		SNATFullyRandom:          false,
		MASQFullyRandom:          false,
		RestoreSupportsLock:      false,
		ChecksumOffloadBroken:    false,
		IPIPDeviceIsL3:           false,
		KernelSideRouteFiltering: false,
	}
}

func (d *FeatureDetector) kernelIsAtLeast(v *Version) (bool, *Version, error) {
	versionReader, err := d.GetKernelVersionReader()
	if err != nil {
		return false, nil, fmt.Errorf("failed to get kernel version reader: %w", err)
	}

	kernelVersion, err := GetKernelVersion(versionReader)
	if err != nil {
		return false, nil, fmt.Errorf("failed to get kernel version: %w", err)
	}

	return kernelVersion.Compare(v) >= 0, kernelVersion, nil
}

// KernelIsAtLeast returns whether the predicate is true or not and an error in
// case it was not able to determine it.
func (d *FeatureDetector) KernelIsAtLeast(v string) (bool, error) {
	ver, err := NewVersion(v)
	if err != nil {
		return false, fmt.Errorf("failed to parse kernel version: %w", err)
	}

	ok, _, err := d.kernelIsAtLeast(ver)

	return ok, err
}

func (d *FeatureDetector) isAtLeastKernel(v *Version) error {
	ok, kernelVersion, err := d.kernelIsAtLeast(v)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("kernel is too old (have: %s but want at least: %s)", kernelVersion, v)
	}

	return nil
}

func (d *FeatureDetector) getDistributionName() string {
	versionReader, err := d.GetKernelVersionReader()
	if err != nil {
		log.Errorf("failed to get kernel version reader: %v", err)
		return DefaultDistro
	}

	kernVersion, err := io.ReadAll(versionReader)
	if err != nil {
		log.WithError(err).Warn("Failed to read kernel version from reader")
		return DefaultDistro
	}
	return GetDistFromString(string(kernVersion))
}

func (d *FeatureDetector) ipipDeviceIsL3() bool {
	switch d.getDistributionName() {
	default:
		return true
	}
}

func (d *FeatureDetector) getIpfwVersion() *Version {
	return d.getKernelVersion()
}

func (d *FeatureDetector) getKernelVersion() *Version {
	reader, err := d.GetKernelVersionReader()
	if err != nil {
		log.WithError(err).Warn("Failed to get the kernel version reader")
		return nil
	}
	kernVersion, err := GetKernelVersion(reader)
	if err != nil {
		log.WithError(err).Warn("Failed to get kernel version")
		return nil
	}
	return kernVersion
}

func (d *FeatureDetector) netlinkSupportsStrict() (bool, error) {
	log.Debug("FreeBSD does not support strict netlink mode")
	return false, nil
}

func countRulesInIptableOutput(in []byte) int {
	count := 0
	for _, x := range bytes.Split(in, []byte("\n")) {
		if len(x) >= 1 && x[0] == '-' {
			count++
		}
	}
	return count
}

// hasKubernetesChains tries to find in the output of the binary if the Kubernetes
// chains exists
func hasKubernetesChains(output []byte) bool {
	return strings.Contains(string(output), "KUBE-IPTABLES-HINT") || strings.Contains(string(output), "KUBE-KUBELET-CANARY")
}

// GetIptablesBackend attempts to detect the iptables backend being used where Felix is running.
// This code is duplicating the detection method found at
// https://github.com/kubernetes-sigs/iptables-wrappers/blob/master/iptables-wrapper-installer.sh#L107
// If there is a specifiedBackend then it is used but if it does not match the detected
// backend then a warning is logged.
func DetectBackend(lookPath func(file string) (string, error), newCmd cmdshim.CmdFactory, specifiedBackend string) string {
	ip6NftSave := FindBestBinary(lookPath, 6, "nft", "save")
	ip4NftSave := FindBestBinary(lookPath, 4, "nft", "save")

	ip6nm, _ := newCmd(ip6NftSave, "-t", "mangle").Output()
	log.WithField("ip6n", string(ip6nm)).Debug("Ip6tables save out")
	ip4nm, _ := newCmd(ip4NftSave, "-t", "mangle").Output()
	log.WithField("ip4n", string(ip4nm)).Debug("Iptables save out")

	var detectedBackend string
	if hasKubernetesChains(ip6nm) || hasKubernetesChains(ip4nm) {
		detectedBackend = "nft"
	} else {
		ip6LgcySave := FindBestBinary(lookPath, 6, "legacy", "save")
		ip4LgcySave := FindBestBinary(lookPath, 4, "legacy", "save")
		ip6lm, _ := newCmd(ip6LgcySave, "-t", "mangle").Output()
		log.WithField("ip6l", string(ip6lm)).Debug("Ip6tables legacy save -t mangle out")
		ip4lm, _ := newCmd(ip4LgcySave, "-t", "mangle").Output()
		log.WithField("ip4l", string(ip4lm)).Debug("Iptables legacy save -t mangle out")

		if hasKubernetesChains(ip6lm) || hasKubernetesChains(ip4lm) {
			detectedBackend = "legacy"
		} else {
			ip6l, _ := newCmd(ip6LgcySave).Output()
			log.WithField("ip6l", string(ip6l)).Debug("Ip6tables legacy save out")
			ip4l, _ := newCmd(ip4LgcySave).Output()
			log.WithField("ip4l", string(ip4l)).Debug("Iptables legacy save out")
			legacyLines := countRulesInIptableOutput(ip6l) + countRulesInIptableOutput(ip4l)

			ip6n, _ := newCmd(ip6NftSave).Output()
			log.WithField("ip6n", string(ip6n)).Debug("Ip6tables save out")
			ip4n, _ := newCmd(ip4NftSave).Output()
			log.WithField("ip4n", string(ip4n)).Debug("Iptables save out")
			nftLines := countRulesInIptableOutput(ip6n) + countRulesInIptableOutput(ip4n)
			if legacyLines >= nftLines {
				detectedBackend = "legacy" // default to legacy mode
			} else {
				detectedBackend = "nft"
			}
		}
	}
	log.WithField("detectedBackend", detectedBackend).Debug("Detected Iptables backend")

	specifiedBackend = strings.ToLower(specifiedBackend)
	if specifiedBackend != "auto" {
		if specifiedBackend != detectedBackend {
			log.WithFields(log.Fields{"detectedBackend": detectedBackend, "specifiedBackend": specifiedBackend}).Warn("Iptables backend specified does not match the detected backend, using specified backend")
		}
		return specifiedBackend
	}
	return detectedBackend
}

// FindBestBinary tries to find an iptables binary for the specific variant (legacy/nftables mode) and returns the name
// of the binary.  Falls back on iptables-restore/iptables-save if the specific variant isn't available.
// Panics if no binary can be found.
func FindBestBinary(lookPath func(file string) (string, error), ipVersion uint8, backendMode, saveOrRestore string) string {
	if lookPath == nil {
		lookPath = exec.LookPath
	}
	verInfix := ""
	if ipVersion == 6 {
		verInfix = "6"
	}
	candidates := []string{
		"ip" + verInfix + "tables-" + backendMode + "-" + saveOrRestore,
		"ip" + verInfix + "tables-" + saveOrRestore,
	}

	logCxt := log.WithFields(log.Fields{
		"ipVersion":     ipVersion,
		"backendMode":   backendMode,
		"saveOrRestore": saveOrRestore,
		"candidates":    candidates,
	})

	for _, candidate := range candidates {
		_, err := lookPath(candidate)
		if err == nil {
			logCxt.WithField("command", candidate).Info("Looked up iptables command")
			return candidate
		}
	}

	logCxt.Panic("Failed to find iptables command")
	return ""
}

type FakeFeatureDetector struct {
	Features
}

func (f *FakeFeatureDetector) FeatureGate(name string) string {
	return ""
}

func (f *FakeFeatureDetector) RefreshFeatures() {
}

func (f *FakeFeatureDetector) GetFeatures() *Features {
	cp := f.Features
	return &cp
}

var _ FeatureDetectorIface = (*FakeFeatureDetector)(nil)
