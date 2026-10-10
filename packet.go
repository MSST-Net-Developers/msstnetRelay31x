package main

import (
	"encoding/binary"
	"errors"
)

// MSST wire format, shared with msst-net-client-core (src/net/packet.rs) and
// unchanged from relay 3.0.x:
//
//	[magic:   4] "MSST"
//	[version: 1] 1
//	[type:    1] see typ* constants
//	[flags:   1] 0 (ignored)
//	[src_id:  8] sender device ID, big-endian u64 (lower 32 bits = 8 hex digits)
//	[dst_id:  8] destination device ID (zero for register/keepalive/ping)
//	[payload: N]
//
// The protocol carries no authentication: src_id is a claim, not proof of
// identity. See README.md "Trust model".
const (
	headerLen       = 4 + 1 + 1 + 1 + 8 + 8 // 23
	protocolVersion = 1

	typRegister          = 0x01
	typKeepalive         = 0x02
	typPunch             = 0x03 // legacy; treated as register (3.0.x behaviour)
	typData              = 0x04
	typPing              = 0x05
	typP2PPing           = 0x06
	typP2PPong           = 0x07
	typDiscoveryRegister = 0x08
	typDiscoveryData     = 0x09

	// pingPayloadLen is the P2P ping/pong payload: seq(4) + timestamp_ms(8).
	pingPayloadLen = 12

	// maxPingEchoLen caps the size of a relay ping (0x05) that is echoed back.
	// Clients send header-only (23 byte) pings; the cap prevents the relay from
	// reflecting large datagrams towards a spoofed source address.
	maxPingEchoLen = 64

	// minIPv4Len is the minimum IPv4 header size carried in discovery data.
	minIPv4Len = 20

	// maxRoomIDLen bounds the room ID carried in discovery data. Coordinator
	// room IDs are "space-" + 8 hex (14 bytes).
	maxRoomIDLen = 64

	// maxDeviceID: device IDs are "device-" + 8 hex digits, so only the lower
	// 32 bits may be set.
	maxDeviceID = 0xFFFFFFFF
)

var (
	errShort   = errors.New("packet too short")
	errMagic   = errors.New("bad magic")
	errVersion = errors.New("unsupported version")
)

// packet is a parsed MSST header. payload and raw alias the receive buffer
// and must not be retained after the handler returns.
type packet struct {
	version byte
	typ     byte
	flags   byte
	srcID   uint64
	dstID   uint64
	payload []byte
	raw     []byte
}

// parsePacket validates framing and returns the parsed header. It does not
// allocate.
func parsePacket(buf []byte) (packet, error) {
	if len(buf) < headerLen {
		return packet{}, errShort
	}
	if !hasMagic(buf) {
		return packet{}, errMagic
	}
	if buf[4] != protocolVersion {
		return packet{}, errVersion
	}
	return packet{
		version: buf[4],
		typ:     buf[5],
		flags:   buf[6],
		srcID:   binary.BigEndian.Uint64(buf[7:15]),
		dstID:   binary.BigEndian.Uint64(buf[15:23]),
		payload: buf[headerLen:],
		raw:     buf,
	}, nil
}

func hasMagic(b []byte) bool {
	return len(b) >= 4 && b[0] == 'M' && b[1] == 'S' && b[2] == 'S' && b[3] == 'T'
}

// validDeviceID reports whether id can correspond to a "device-XXXXXXXX" ID.
// Zero is what the client encodes when its device ID fails to parse.
func validDeviceID(id uint64) bool {
	return id != 0 && id <= maxDeviceID
}

// parseDiscoveryPayload splits a TYPE_DISCOVERY_DATA payload:
//
//	[room_id_len: 1][room_id: N][ipv4_packet: M]
//
// The room ID must be non-empty and limited to [A-Za-z0-9_-] because it is
// used as a Coordinator URL path segment. The IP packet must look like IPv4
// (the only family the client discovery receiver accepts).
func parseDiscoveryPayload(p []byte) (roomID, ipPkt []byte, ok bool) {
	if len(p) < 1 {
		return nil, nil, false
	}
	n := int(p[0])
	if n == 0 || n > maxRoomIDLen || len(p) < 1+n+minIPv4Len {
		return nil, nil, false
	}
	roomID = p[1 : 1+n]
	for _, c := range roomID {
		if !validRoomIDChar(c) {
			return nil, nil, false
		}
	}
	ipPkt = p[1+n:]
	if ipPkt[0]>>4 != 4 {
		return nil, nil, false
	}
	return roomID, ipPkt, true
}

func validRoomIDChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_'
}

// validRoomID applies the same rule as parseDiscoveryPayload to a string.
func validRoomID(s string) bool {
	if len(s) == 0 || len(s) > maxRoomIDLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !validRoomIDChar(s[i]) {
			return false
		}
	}
	return true
}
