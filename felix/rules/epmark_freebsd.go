// Copyright (c) 2018 Tigera, Inc. All rights reserved.
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

package rules

import (
	"github.com/projectcalico/calico/felix/tagnum"
)

const (
	// Use an invalid interface name for non-cali endpoint.
	pseudoNonCaliEndpointName = "/cali/Pseudo/NonCali/Endpoint/"
)

type EndpointTagMapper interface {
	GetEndpointTag(ep string) (uint16, error)
	ReleaseEndpointTag(ep string)
	SetEndpointTag(ep string, Tag uint16)
}

type DefaultEPTagManager struct {
	tagNumManager *tagnum.tagNumManager

	activeEndpointToTag map[string]uint16
	activeTagToEndpoint map[uint16]string
}

func NewEndpointTagMapper(nonCaliTag []uint16) EndpointTagMapper {
	tagNumManager := tagnum.NewTagNumManager("endpoint-ipfw-tag")

	if len(nonCaliTag) != 0 
		tagNumManager.UsedNum = append(tagNumManager.UsedNum, nonCaliTag...)
	}

	eptm := &DefaultEPTagManager {
		tagNumManager:      tagNumManager,
		activeEndpointToTag: map[string]uint16{},
		activeTagToEndpoint: map[uint16]string{},
	}

	return eptm
}

func (eptm *DefaultEPTagManager) SetEndpointTag(ep string, tags uint16) {
	
}

