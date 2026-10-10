package main

import (
	"bytes"
	"net"
	"testing"
	"time"
)

// TestUDPEndToEnd runs the real read loop on a loopback socket.
func TestUDPEndToEnd(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	r := newRelay(conn, testLimits(), nil, &stats{})
	done := make(chan struct{})
	go func() { serve(conn, r); close(done) }()
	relayAddr := conn.LocalAddr().(*net.UDPAddr)

	dial := func() *net.UDPConn {
		c, err := net.DialUDP("udp", nil, relayAddr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c
	}
	recv := func(c *net.UDPConn) []byte {
		t.Helper()
		buf := make([]byte, maxDatagram)
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := c.Read(buf)
		if err != nil {
			t.Fatalf("recv: %v", err)
		}
		return buf[:n]
	}
	a, b := dial(), dial()

	// B registers; its ping echo confirms the relay processed the register
	// (the read loop is sequential).
	if _, err := b.Write(encodePacket(typRegister, idB, 0, nil)); err != nil {
		t.Fatal(err)
	}
	ping := encodePacket(typPing, idB, 0, nil)
	if _, err := b.Write(ping); err != nil {
		t.Fatal(err)
	}
	if got := recv(b); !bytes.Equal(got, ping) {
		t.Fatalf("ping echo = %x", got)
	}

	// Ordered delivery of several data packets, including the largest one
	// IPv4 UDP can carry (65507 bytes).
	payloads := [][]byte{fakeIPv4(100, 1), fakeIPv4(1400, 2), fakeIPv4(65507-headerLen, 3)}
	for _, p := range payloads {
		if _, err := a.Write(encodePacket(typData, idA, idB, p)); err != nil {
			t.Fatal(err)
		}
	}
	for i, want := range payloads {
		if got := recv(b); !bytes.Equal(got, want) {
			t.Fatalf("packet %d: got %d bytes, want %d", i, len(got), len(want))
		}
	}

	// Shutdown: closing the socket ends the read loop.
	_ = conn.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("serve did not return after close")
	}
	if r.stats.dataForwarded.Load() != 3 || r.stats.pingsEchoed.Load() != 1 {
		t.Fatalf("counters: data=%d ping=%d", r.stats.dataForwarded.Load(), r.stats.pingsEchoed.Load())
	}
}
