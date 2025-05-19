// Copyright (c) 2021 Tigera, Inc. All rights reserved.
//
// Based on the version in the Weave project, Copyright Weaveworks:
// https://github.com/weaveworks/weave/blob/c69e140e9e43d456b6fe5812a2bc61bc67953b93/net/ethtool.go
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

package ethtool

import (
	"fmt"
	"os"
	"os/exec"
)

const (
	EthtoolRxGRO = "rx-gro"
)

func EthtoolTXOff(name string) error {
	cmd := exec.Command("ifconfig", name, "txcsum")
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Fprintln(os.Stderr, string(out))
	}
	return err
}

func EthtoolChangeImpl(iface string, config map[string]bool) error {
	// not supported.
	return nil
}
