package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// encodePacket mirrors MsstPacket::encode in msst-net-client-core.
func encodePacket(typ byte, src, dst uint64, payload []byte) []byte {
	b := make([]byte, headerLen, headerLen+len(payload))
	copy(b, "MSST")
	b[4] = protocolVersion
	b[5] = typ
	binary.BigEndian.PutUint64(b[7:15], src)
	binary.BigEndian.PutUint64(b[15:23], dst)
	return append(b, payload...)
}

// fakeIPv4 returns a minimal IPv4-looking packet of n bytes (n >= 20).
func fakeIPv4(n int, fill byte) []byte {
	b := bytes.Repeat([]byte{fill}, n)
	b[0] = 0x45
	return b
}

func discoveryPayload(room string, ip []byte) []byte {
	p := []byte{byte(len(room))}
	p = append(p, room...)
	return append(p, ip...)
}

func TestParsePacket(t *testing.T) {
	raw := encodePacket(typData, 0xa1b2c3d4, 0x01020304, []byte{0x45, 1, 2})
	p, err := parsePacket(raw)
	if err != nil {
		t.Fatal(err)
	}
	if p.typ != typData || p.srcID != 0xa1b2c3d4 || p.dstID != 0x01020304 {
		t.Fatalf("bad header: %+v", p)
	}
	if !bytes.Equal(p.payload, []byte{0x45, 1, 2}) || len(p.raw) != len(raw) {
		t.Fatalf("bad payload: %x", p.payload)
	}

	hdrOnly, err := parsePacket(encodePacket(typRegister, 1, 0, nil))
	if err != nil || len(hdrOnly.payload) != 0 {
		t.Fatalf("header-only packet: %v %d", err, len(hdrOnly.payload))
	}
}

func TestParsePacketRejects(t *testing.T) {
	good := encodePacket(typData, 1, 2, []byte{0x45})
	badMagic := bytes.Clone(good)
	badMagic[3] = 'X'
	badVersion := bytes.Clone(good)
	badVersion[4] = 2

	cases := []struct {
		name string
		in   []byte
		want error
	}{
		{"empty", nil, errShort},
		{"short", good[:headerLen-1], errShort},
		{"magic", badMagic, errMagic},
		{"version", badVersion, errVersion},
	}
	for _, c := range cases {
		if _, err := parsePacket(c.in); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v want %v", c.name, err, c.want)
		}
	}
}

func TestValidDeviceID(t *testing.T) {
	for id, want := range map[uint64]bool{0: false, 1: true, 0xffffffff: true, 0x1_0000_0000: false} {
		if validDeviceID(id) != want {
			t.Errorf("validDeviceID(%#x) != %v", id, want)
		}
	}
}

func TestParseDiscoveryPayload(t *testing.T) {
	ip := fakeIPv4(28, 0)
	room, pkt, ok := parseDiscoveryPayload(discoveryPayload("space-0a1b2c3d", ip))
	if !ok || string(room) != "space-0a1b2c3d" || !bytes.Equal(pkt, ip) {
		t.Fatalf("valid payload rejected: ok=%v room=%q", ok, room)
	}

	ipv6 := fakeIPv4(40, 0)
	ipv6[0] = 0x60
	long := make([]byte, maxRoomIDLen+1)
	for i := range long {
		long[i] = 'a'
	}
	bad := map[string][]byte{
		"empty":         nil,
		"empty room":    discoveryPayload("", ip),
		"short ip":      discoveryPayload("r", ip[:19]),
		"len overrun":   {200, 'a', 'b'},
		"path chars":    discoveryPayload("../relays", ip),
		"slash":         discoveryPayload("a/b", ip),
		"percent":       discoveryPayload("a%2f", ip),
		"not ipv4":      discoveryPayload("r", ipv6),
		"room too long": discoveryPayload(string(long), ip),
	}
	for name, in := range bad {
		if _, _, ok := parseDiscoveryPayload(in); ok {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParseDeviceID(t *testing.T) {
	if id, ok := parseDeviceID("device-a1b2c3d4"); !ok || id != 0xa1b2c3d4 {
		t.Fatalf("got %x %v", id, ok)
	}
	for _, s := range []string{"", "device-", "device-00000000", "device-a1b2c3d", "device-a1b2c3d4e", "dev-a1b2c3d4", "device-zzzzzzzz", "device-+1b2c3d4"} {
		if _, ok := parseDeviceID(s); ok {
			t.Errorf("%q accepted", s)
		}
	}
}

func BenchmarkParsePacket(b *testing.B) {
	raw := encodePacket(typData, 1, 2, make([]byte, 1400))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := parsePacket(raw); err != nil {
			b.Fatal(err)
		}
	}
}
