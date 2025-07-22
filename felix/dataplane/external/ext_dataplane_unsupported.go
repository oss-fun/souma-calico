// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.
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

// extdataplane implements the connection to an external dataplane driver, connected via
// a pair of pipes.

//go:build freebsd

package extdataplane

import (
	"fmt"
	"io"
	"os/exec"

	"github.com/projectcalico/calico/felix/proto"
)

func StartExtDataplaneDriver(_ string) (*extDataplaneConn, *exec.Cmd) {
	return nil, nil
}

type extDataplaneConn struct {
	fromDataplane io.Reader
	toDataplane   io.Writer
	nextSeqNumber uint64
}

func (c *extDataplaneConn) RecvMessage() (interface{}, error) {
	return nil, fmt.Errorf("extdataplane.RecvMessage: Unsupported")
}

func (fc *extDataplaneConn) SendMessage(_ interface{}) error {
	return fmt.Errorf("extdataplane.SendMessage: Unsupported")
}

func WrapPayloadWithEnvelope(_ interface{}, _ uint64) (*proto.ToDataplane, error) {
	return nil, fmt.Errorf("extdataplane.WrapPlayloadEnvelope: Unsupported")
}
