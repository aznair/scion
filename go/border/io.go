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

package main

import (
	"net"
	"time"

	log "github.com/inconshreveable/log15"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/netsec-ethz/scion/go/border/metrics"
	"github.com/netsec-ethz/scion/go/border/packet"
	"github.com/netsec-ethz/scion/go/lib/log"
)

func (r *Router) getPktBuf() *packet.Packet {
	// https://golang.org/doc/effective_go.html#leaky_buffer
	var p *packet.Packet
	select {
	case p = <-r.freePkts:
		// Got one
		metrics.PktBufReuse.Inc()
		return p
	default:
		// None available, allocate a new one
		metrics.PktBufNew.Inc()
		p = new(packet.Packet)
		p.Raw = make([]byte, pktBufSize)
		return p
	}
}

func (r *Router) readPosixInput(in *net.UDPConn, dirFrom packet.Dir, labels prometheus.Labels,
	q chan *packet.Packet) {
	defer liblog.PanicLog()
	log.Info("Listening", "addr", in.LocalAddr())
	dst := in.LocalAddr().(*net.UDPAddr)
	for {
		metrics.InputLoops.With(labels).Inc()
		p := r.getPktBuf()
		p.DirFrom = dirFrom
		start := time.Now()
		length, src, err := in.ReadFromUDP(p.Raw)
		if err != nil {
			log.Error("Error reading from socket", "socket", dst, "err", err)
			continue
		}
		t := time.Now().Sub(start).Seconds()
		metrics.InputProcessTime.With(labels).Add(t)
		p.TimeIn = time.Now()
		p.Raw = p.Raw[:length] // Set the length of the slice
		p.Ingress.Src = src
		p.Ingress.Dst = dst
		metrics.PktsRecv.With(labels).Inc()
		metrics.BytesRecv.With(labels).Add(float64(length))
		q <- p
	}
}

func (r *Router) writeLocalOutput(out *net.UDPConn, labels prometheus.Labels, p *packet.Packet) {
	if len(p.Egress) == 0 {
		p.Error("Destination not specified")
		return
	}
	for _, epair := range p.Egress {
		start := time.Now()
		if count, err := out.WriteToUDP(p.Raw, epair.Dst); err != nil {
			p.Error("Error sending packet", "err", err)
			return
		} else if count != len(p.Raw) {
			p.Error("Unable to write full packet", "len", count)
			return
		}
		t := time.Now().Sub(start).Seconds()
		metrics.OutputProcessTime.With(labels).Add(t)
		metrics.BytesSent.With(labels).Add(float64(len(p.Raw)))
		metrics.PktsSent.With(labels).Inc()
	}
}

func (r *Router) writeIntfOutput(out *net.UDPConn, labels prometheus.Labels, p *packet.Packet) {
	if len(p.Egress) == 0 {
		p.Error("Destination not specified")
		return
	}
	start := time.Now()
	if count, err := out.Write(p.Raw); err != nil {
		p.Error("Error sending packet", "err", err)
		return
	} else if count != len(p.Raw) {
		p.Error("Unable to write full packet", "len", count)
		return
	}
	t := time.Now().Sub(start).Seconds()
	metrics.OutputProcessTime.With(labels).Add(t)
	metrics.BytesSent.With(labels).Add(float64(len(p.Raw)))
	metrics.PktsSent.With(labels).Inc()
}
