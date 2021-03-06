// Copyright 2016 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package packet

import (
	"github.com/netsec-ethz/scion/go/lib/util"
)

const (
	ErrorPayloadLenWrong = "Payload length is wrong"
	ErrorPayloadDecode   = "Payload decoding failed"
	ErrorPayloadParse    = "Payload parseing failed"
)

// No fallback for payload - a hook must be registered to read it.
func (p *Packet) Payload() (interface{}, *util.Error) {
	if p.pld == nil && len(p.hooks.Payload) > 0 {
		_, err := p.L4Hdr()
		if err != nil {
			return nil, err
		}
		for _, f := range p.hooks.Payload {
			ret, pld, err := f()
			switch {
			case err != nil:
				return nil, err
			case ret == HookContinue:
				continue
			case ret == HookFinish:
				p.pld = pld
				return p.pld, nil
			}
		}
	}
	return p.pld, nil
}
