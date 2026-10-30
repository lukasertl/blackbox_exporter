// Copyright 2016 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package prober

import (
	"context"
	"log/slog"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/prometheus/blackbox_exporter/config"
)

var (
	icmpSequence      uint16
	icmpSequenceMutex sync.Mutex
)

func init() {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	// Start the ICMP echo sequence at a random offset to prevent them from
	// being in sync when several blackbox_exporter instances are restarted
	// at the same time. See #411.
	icmpSequence = uint16(r.Intn(1 << 16))
}

func getRandomICMPID() int {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	// Generate a random ICMP ID for each probe to avoid potential clashes
	// with other blackbox_exporter instances or concurrent probes.
	return r.Intn(1 << 16)
}

func getICMPSequence() uint16 {
	icmpSequenceMutex.Lock()
	defer icmpSequenceMutex.Unlock()
	icmpSequence++
	return icmpSequence
}

func ProbeICMP(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger *slog.Logger) (success bool) {
	var (
		requestType icmp.Type
		icmpConn    *icmp.PacketConn

		durationGaugeVec = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "probe_icmp_duration_seconds",
			Help: "Duration of icmp request by phase",
		}, []string{"phase"})
	)

	for _, lv := range []string{"resolve", "setup", "rtt"} {
		durationGaugeVec.WithLabelValues(lv)
	}

	registry.MustRegister(durationGaugeVec)

	dstIPAddr, lookupTime, err := chooseProtocol(ctx, module.ICMP.IPProtocol, module.ICMP.IPProtocolFallback, target, registry, logger)
	if err != nil {
		logger.Error("Error resolving address", "err", err)
		return false
	}
	durationGaugeVec.WithLabelValues("resolve").Add(lookupTime)

	var srcIP net.IP
	if len(module.ICMP.SourceIPAddress) > 0 {
		if srcIP = net.ParseIP(module.ICMP.SourceIPAddress); srcIP == nil {
			logger.Error("Error parsing source ip address", "srcIP", module.ICMP.SourceIPAddress)
			return false
		}
		logger.Debug("Using source address", "srcIP", srcIP)
	}

	setupStart := time.Now()
	logger.Debug("Creating socket")

	requestType = ipv4.ICMPTypeEcho

	if srcIP == nil {
		srcIP = net.ParseIP("0.0.0.0")
	}

	icmpConn, err = icmp.ListenPacket("udp4", srcIP.String())
	if err != nil {
		logger.Debug("Unable to do unprivileged listen on socket, will attempt privileged", "err", err)
	}
	defer icmpConn.Close()

	var dst net.Addr = dstIPAddr
	dst = &net.UDPAddr{IP: dstIPAddr.IP, Zone: dstIPAddr.Zone}

	var data []byte
	if module.ICMP.PayloadSize != 0 {
		data = make([]byte, module.ICMP.PayloadSize)
		copy(data, "Prometheus Blackbox Exporter")
	} else {
		data = []byte("Prometheus Blackbox Exporter")
	}

	body := &icmp.Echo{
		ID:   getRandomICMPID(),
		Seq:  int(getICMPSequence()),
		Data: data,
	}
	logger.Debug("Creating ICMP packet", "seq", body.Seq, "id", body.ID)
	wm := icmp.Message{
		Type: requestType,
		Code: 0,
		Body: body,
	}

	wb, err := wm.Marshal(nil)
	if err != nil {
		logger.Error("Error marshalling packet", "err", err)
		return
	}

	durationGaugeVec.WithLabelValues("setup").Add(time.Since(setupStart).Seconds())

	rb := make([]byte, 65536)
	deadline, _ := ctx.Deadline()
	var rttStart time.Time

	err = icmpConn.SetReadDeadline(deadline)
	if err != nil {
		logger.Error("Error setting socket deadline", "err", err)
		return
	}

	logger.Debug("Writing out packet")
	rttStart = time.Now()
	_, err = icmpConn.WriteTo(wb, dst)
	if err != nil {
		logger.Warn("Error writing to socket", "err", err)
		return
	}

	logger.Debug("Waiting for reply packets")
	for {
		var peer net.Addr
		var err error
		var rtt float64

		_, peer, err = icmpConn.ReadFrom(rb)
		rtt = time.Since(rttStart).Seconds()
		if err != nil {
			if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
				logger.Warn("Timeout reading from socket", "err", err)
				return
			}
			logger.Error("Error reading from socket", "err", err)
			continue
		}
		if peer.String() != dst.String() {
			continue
		}

		// Reply should be the same except for the message type and ID if
		// unprivileged sockets were used and the kernel used its own.
		if err != nil {
			logger.Error("Error marshalling packet", "err", err)
			return
		}

		durationGaugeVec.WithLabelValues("rtt").Add(rtt)
		logger.Debug("Found matching reply packet")
		return true
	}
}
