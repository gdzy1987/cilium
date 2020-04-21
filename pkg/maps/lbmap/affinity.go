// Copyright 2020 Authors of Cilium
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

package lbmap

import (
	"fmt"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
)

const (
	AffinityMatchMapName = "cilium_lb_affinity_match"
)

var (
	AffinityMatchMap = bpf.NewMap(
		AffinityMatchMapName,
		bpf.MapTypeHash,
		&AffinityMatchKey{},
		int(unsafe.Sizeof(AffinityMatchKey{})),
		&AffinityMatchValue{},
		int(unsafe.Sizeof(AffinityMatchValue{})),
		MaxEntries,
		0, 0,
		func(key []byte, value []byte, mapKey bpf.MapKey, mapValue bpf.MapValue) (bpf.MapKey, bpf.MapValue, error) {
			aKey, aVal := mapKey.(*AffinityMatchKey), mapValue.(*AffinityMatchValue)

			if _, _, err := bpf.ConvertKeyValue(key, value, aKey, aVal); err != nil {
				return nil, nil, err
			}

			return aKey, aVal, nil
		}).WithCache()
)

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type AffinityMatchKey struct {
	backendID uint32 `align:"backend_id"`
	revNATID  uint16 `align:"rev_nat_id"`
	pad       uint16 `align:"pad"`
}

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type AffinityMatchValue struct {
	pad uint8 `align:"pad"`
}

// NewAffinityMatchKey creates the AffinityMatch key
func NewAffinityMatchKey(revNATID uint16, backendID uint32) *AffinityMatchKey {
	return &AffinityMatchKey{
		backendID: backendID,
		revNATID:  revNATID,
	}
}

// GetKeyPtr returns the unsafe pointer to the BPF key
func (k *AffinityMatchKey) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

// GetValuePtr returns the unsafe pointer to the BPF value
func (v *AffinityMatchValue) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

// String converts the key into a human readable string format
func (k *AffinityMatchKey) String() string { return fmt.Sprintf("%d %d", k.backendID, k.revNATID) }

// String converts the value into a human readable string format
func (v *AffinityMatchValue) String() string { return "" }

// NewValue returns a new empty instance of the structure representing the BPF
// map value
func (k *AffinityMatchKey) NewValue() bpf.MapValue { return &AffinityMatchValue{} }

// ToNetwork returns the key in the network byte order
func (k *AffinityMatchKey) ToNetwork() *AffinityMatchKey {
	n := *k
	// For some reasons rev_nat_index is stored in network byte order in
	// the SVC BPF maps
	n.revNATID = byteorder.HostToNetwork(n.revNATID).(uint16)
	return &n
}
