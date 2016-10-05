// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package header

import (
	"encoding/binary"

	"github.com/google/netstack/tcpip"
)

// ICMPv6 represents an ICMPv6 header stored in a byte array.
type ICMPv6 []byte

const (
	ICMPv6MinimumSize = 4

	ICMPv6ProtocolNumber tcpip.TransportProtocolNumber = 58
)

type ICMPv6Type byte

const (
	DstUnreachable         ICMPv6Type = 1 // RFC 2463
	PacketTooBig           ICMPv6Type = 2
	TimeExceeded           ICMPv6Type = 3
	ParamProblem           ICMPv6Type = 4
	EchoRequest            ICMPv6Type = 128
	EchoReply              ICMPv6Type = 129
	NeighborSolicitation   ICMPv6Type = 135 // RFC 4861
	NeighborAdvertisements ICMPv6Type = 136
)

func (b ICMPv6) Type() ICMPv6Type { return ICMPv6Type(b[0]) }
func (b ICMPv6) Code() byte       { return b[1] }
func (b ICMPv6) SetChecksum(checksum uint16) {
	binary.BigEndian.PutUint16(b[2:], checksum)
}
func (b ICMPv6) SetType(t ICMPv6Type) { b[0] = byte(t) }
func (b ICMPv6) SetCode(c byte)       { b[1] = c }
func (b ICMPv6) CalculateChecksum(partialChecksum uint16, totalLen int) uint16 {
	tmp := make([]byte, 2)
	binary.BigEndian.PutUint16(tmp, uint16(totalLen))
	checksum := Checksum(tmp, partialChecksum)
	return Checksum(b[:ICMPv6MinimumSize], checksum)
}
