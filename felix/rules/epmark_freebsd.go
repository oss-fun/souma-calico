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
	"errors"
	"hash/fnv"

	"github.com/projectcalico/calico/felix/tagnum"
)

const (
	// Use an invalid interface name for non-cali endpoint.
	pseudoNonCaliEndpointName = "/cali/Pseudo/NonCali/Endpoint/"
)

type EndpointTagMapper interface {
	GetEndpointTag(ep string) (uint16, error)
	ReleaseEndpointTag(ep string)
	SetEndpointTag(ep string, Tag uint16) error
}

type DefaultEPTagManager struct {
	tagNumManager *tagnum.TagNumManager
	maxPosition uint16

	hash32 HashCalculator32

	activeEndpointToTag map[string]uint16
	activeTagToEndpoint map[uint16]string
}

func NewEndpointTagMapper(nonCaliTag []uint16) EndpointTagMapper {
	tagNumManager := tagnum.NewTagNumManager("endpoint-ipfw-tag")

	if len(nonCaliTag) != 0 {
		tagNumManager.UsedNum = append(tagNumManager.UsedNum, nonCaliTag...)
	}

	eptm := &DefaultEPTagManager {
		tagNumManager:      tagNumManager,
		activeEndpointToTag: map[string]uint16{},
		activeTagToEndpoint: map[uint16]string{},
	}

	return eptm
}

func (eptm *DefaultEPTagManager) GetEndpointTag(ep string) (uint16, error) {
	length := len(ep)
	if length == 0 {
		return 0, errors.New("Invalid endpoint name")
	}

	if tag, ok := eptm.activeEndpointToTag[ep]; ok {
		return tag, nil
	}

	_, err := eptm.hash32.Write([]byte(ep))
	if err != nil {
		return 0, errors.New("Failed to hash endpoint")
	}
	hashVal := eptm.hash32.Sum32()
	eptm.hash32.Reset()

	var result uint16
	result = uint16(hashVal & 0xffff)

	gotOne := false
	for ; result < 65535; result++ {
		if prospect == 0 {
			continue
		}
		if _, exists := eptm.activeTagtoEndpoint[result]; !exists {
			gotOne = true
			break
		}
	}

	if !gotOne {
		return 0, errors.New("No mark left for endpoint")
	}

	eptm.setTag(ep, result)

	return 
}

func (eptm *DefaultEPTagManager) ReleaseEndpointTag(ep string) {

}

func (eptm *DefaultEPTagManager) SetEndpointTag(ep string, tags uint16) error {
	
}

func (eptm *DefaultEPTagManager) deleteTag(ep string, tag uint16) {
	delete(eptm.activeTagToEndpoint, tag)
	delete(eptm.activeEndpointToTag, ep)
}

func (eptm *DefaultEPTagManager) setTag(ep string, tag uint16) {
	eptm.activeEndpointToTag[ep] = tag
	eptm.activeTagToEndpoint[tag] = ep
}

type HashCalculator32 interface {
	io.Writer

	Sum32() uint32

	Reset()
}

