package main

import (
	"encoding/binary"
	"net"
	"sync/atomic"
	"time"
)

// All relay streams serve one local WireGuard socket. The server chooses its
// return stream independently of the stream that carried the outbound packet.
type localPeer struct {
	addr   atomic.Pointer[net.Addr]
	lastRx atomic.Int64
}

func (p *localPeer) observe(addr net.Addr) {
	p.addr.Store(&addr)
}

func (p *localPeer) writeTo(out net.PacketConn, packet []byte) (int, error) {
	addr := p.addr.Load()
	if addr == nil {
		return 0, nil
	}
	return out.WriteTo(packet, *addr)
}

func (p *localPeer) received(now time.Time) {
	p.lastRx.Store(now.UnixNano())
}

type trafficWatchdog struct {
	pendingSince time.Time
}

func (w *trafficWatchdog) stalled(peer *localPeer, now time.Time, timeout time.Duration) bool {
	if w.pendingSince.IsZero() {
		return false
	}
	if peer.lastRx.Load() >= w.pendingSince.UnixNano() {
		w.pendingSince = time.Time{}
		return false
	}
	return timeout > 0 && now.Sub(w.pendingSince) > timeout
}

func (w *trafficWatchdog) sent(now time.Time, packet []byte) {
	// WireGuard's empty transport message is a one-way keepalive, not a request
	// that the peer must answer (MessageKeepaliveSize=32, MessageTransportType=4).
	if len(packet) == 32 && binary.LittleEndian.Uint32(packet[:4]) == 4 {
		return
	}
	if w.pendingSince.IsZero() {
		w.pendingSince = now
	}
}
