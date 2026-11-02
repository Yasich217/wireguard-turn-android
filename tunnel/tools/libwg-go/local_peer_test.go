package main

import (
	"net"
	"testing"
	"time"
)

func localUDPSocket(t *testing.T) net.PacketConn {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func receiveLocalPacket(t *testing.T, conn net.PacketConn, want string) net.Addr {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 256)
	n, addr, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != want {
		t.Fatalf("received %q, want %q", buf[:n], want)
	}
	return addr
}

func TestLocalPeerReturnsRepliesFromAnyStream(t *testing.T) {
	wg := localUDPSocket(t)
	hub := localUDPSocket(t)
	otherStream := localUDPSocket(t)
	peer := &localPeer{}
	if n, err := peer.writeTo(otherStream, []byte("early")); n != 0 || err != nil {
		t.Fatalf("unexpected reply before learning WireGuard address: n=%d err=%v", n, err)
	}
	if _, err := wg.WriteTo([]byte("handshake"), hub.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	peer.observe(receiveLocalPacket(t, hub, "handshake"))

	// An independently selected return stream has never received a local packet.
	for _, out := range []net.PacketConn{otherStream, hub} {
		if _, err := peer.writeTo(out, []byte("reply")); err != nil {
			t.Fatal(err)
		}
		receiveLocalPacket(t, wg, "reply")
	}

	// A userspace backend restart can replace its local UDP socket.
	replacement := localUDPSocket(t)
	if _, err := replacement.WriteTo([]byte("new handshake"), hub.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	peer.observe(receiveLocalPacket(t, hub, "new handshake"))
	if _, err := peer.writeTo(otherStream, []byte("new reply")); err != nil {
		t.Fatal(err)
	}
	receiveLocalPacket(t, replacement, "new reply")
}

func TestTrafficWatchdogAcceptsRepliesOnAnotherStream(t *testing.T) {
	peer := &localPeer{}
	watchdog := &trafficWatchdog{}
	start := time.Unix(1000, 0)
	watchdog.sent(start, []byte("data"))
	peer.received(start.Add(time.Second))
	if watchdog.stalled(peer, start.Add(2*time.Minute), time.Minute) {
		t.Fatal("a reply on another stream must keep the hub healthy")
	}
	watchdog.sent(start.Add(2*time.Minute), []byte("data"))
	if watchdog.stalled(peer, start.Add(2*time.Minute+time.Second), time.Minute) {
		t.Fatal("fresh traffic must get a new response window")
	}
}

func TestTrafficWatchdogExpiresContinuousUnansweredTraffic(t *testing.T) {
	peer := &localPeer{}
	watchdog := &trafficWatchdog{}
	start := time.Unix(1000, 0)
	watchdog.sent(start, []byte("data"))
	for second := 1; second <= 60; second++ {
		now := start.Add(time.Duration(second) * time.Second)
		if watchdog.stalled(peer, now, time.Minute) {
			t.Fatalf("response window ended early at second %d", second)
		}
		watchdog.sent(now, []byte("data"))
	}
	if !watchdog.stalled(peer, start.Add(61*time.Second), time.Minute) {
		t.Fatal("outbound traffic must not continually postpone recovery")
	}
}

func TestTrafficWatchdogPreservesIdleAndDisabledStreams(t *testing.T) {
	peer := &localPeer{}
	watchdog := &trafficWatchdog{}
	start := time.Unix(1000, 0)
	if watchdog.stalled(peer, start, time.Minute) {
		t.Fatal("an idle stream is healthy")
	}
	watchdog.sent(start, []byte("data"))
	if watchdog.stalled(peer, start.Add(time.Hour), 0) {
		t.Fatal("a disabled watchdog must not restart streams")
	}
}

func TestTrafficWatchdogDoesNotExpectKeepaliveReplies(t *testing.T) {
	peer := &localPeer{}
	watchdog := &trafficWatchdog{}
	start := time.Unix(1000, 0)
	keepalive := make([]byte, 32)
	keepalive[0] = 4
	for second := 0; second < 180; second += 25 {
		now := start.Add(time.Duration(second) * time.Second)
		if watchdog.stalled(peer, now, time.Minute) {
			t.Fatal("one-way keepalives must not trigger reconnects while idle")
		}
		watchdog.sent(now, keepalive)
	}
	watchdog.sent(start.Add(3*time.Minute), []byte("data"))
	if !watchdog.stalled(peer, start.Add(4*time.Minute+time.Second), time.Minute) {
		t.Fatal("real unanswered data must still trigger recovery")
	}
}
