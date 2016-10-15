// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package header

import (
	"encoding/binary"

	"github.com/google/netstack/tcpip"
)

// ICMPv4 represents an ICMPv4 header stored in a byte array.
type ICMPv4 []byte

const (
	ICMPv4MinimumSize = 4

	ICMPv4ProtocolNumber tcpip.TransportProtocolNumber = 1
)

type ICMPv4Type byte

const (
	ICMPv4EchoReply      ICMPv4Type = 0 // RFC 792
	ICMPv4DstUnreachable ICMPv4Type = 3
	ICMPv4SrcQuench      ICMPv4Type = 4
	ICMPv4Redirect       ICMPv4Type = 5
	ICMPv4Echo           ICMPv4Type = 8
	ICMPv4TimeExceeded   ICMPv4Type = 11
	ICMPv4ParamProblem   ICMPv4Type = 12
	ICMPv4Timestamp      ICMPv4Type = 13
	ICMPv4TimestampReply ICMPv4Type = 14
	ICMPv4InfoRequest    ICMPv4Type = 15
	ICMPv4InfoReply      ICMPv4Type = 16
)

func (b ICMPv4) Type() ICMPv4Type { return ICMPv4Type(b[0]) }
func (b ICMPv4) Code() byte       { return b[1] }
func (b ICMPv4) SetChecksum(checksum uint16) {
	binary.BigEndian.PutUint16(b[2:], checksum)
}
func (b ICMPv4) SetType(t ICMPv4Type) { b[0] = byte(t) }
func (b ICMPv4) SetCode(c byte)       { b[1] = c }
