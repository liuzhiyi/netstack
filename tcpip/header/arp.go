// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package header

import "github.com/google/netstack/tcpip"

const (
	ARPProtocolNumber tcpip.NetworkProtocolNumber = 0x0806

	ARPSize = 2 + 2 + 1 + 1 + 2 + 4*6
)

type ARPOp uint16

const (
	ARPRequest ARPOp = 1
	ARPReply   ARPOp = 2
)

type ARP []byte

func (a ARP) hardwareAddressSpace() uint16 { return uint16(a[0])<<8 | uint16(a[1]) }
func (a ARP) protocolAddressSpace() uint16 { return uint16(a[2])<<8 | uint16(a[3]) }
func (a ARP) hardwareAddressSize() int     { return int(a[4]) }
func (a ARP) protocolAddressSize() int     { return int(a[5]) }
func (a ARP) Op() ARPOp                    { return ARPOp(a[6])<<8 | ARPOp(a[7]) }
func (a ARP) SetOp(op ARPOp) {
	a[6] = uint8(op >> 8)
	a[7] = uint8(op)
}

func (a ARP) HardwareAddressSender() []byte {
	const s = 8
	return a[s : s+6]
}
func (a ARP) ProtocolAddressSender() []byte {
	const s = 8 + 6
	return a[s : s+4]
}
func (a ARP) HardwareAddressTarget() []byte {
	const s = 8 + 6 + 4
	return a[s : s+6]
}
func (a ARP) ProtocolAddressTarget() []byte {
	const s = 8 + 6 + 4 + 6
	return a[s : s+4]
}

// IsValid reports whether this is an ARP packet for IPv4 over Ethernet.
func (a ARP) IsValid() bool {
	const htypeEthernet = 1
	const macSize = 6
	return a.hardwareAddressSpace() == htypeEthernet &&
		a.protocolAddressSpace() == uint16(IPv4ProtocolNumber) &&
		a.hardwareAddressSize() == macSize &&
		a.protocolAddressSize() == IPv4AddressSize
}
