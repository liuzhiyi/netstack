// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package arp

import (
	"fmt"

	"github.com/google/netstack/tcpip"
	"github.com/google/netstack/tcpip/buffer"
	"github.com/google/netstack/tcpip/header"
	"github.com/google/netstack/tcpip/stack"
)

const (
	ProtocolName   = "arp"
	ProtocolNumber = header.ARPProtocolNumber
)

type endpoint struct {
	nicid      tcpip.NICID
	linkEP     stack.LinkEndpoint
	dispatcher stack.TransportDispatcher
	stack      *stack.Stack
}

// MTU implements stack.NetworkEndpoint.MTU. It returns the link-layer MTU minus
// the network layer max header length.
func (e *endpoint) MTU() uint32 {
	lmtu := e.linkEP.MTU()
	return lmtu - uint32(e.MaxHeaderLength())
}

// NICID returns the ID of the NIC this endpoint belongs to.
func (e *endpoint) NICID() tcpip.NICID {
	return e.nicid
}

func (e *endpoint) ID() *stack.NetworkEndpointID {
	return &stack.NetworkEndpointID{}
}

func (e *endpoint) MaxHeaderLength() uint16 {
	return e.linkEP.MaxHeaderLength() + header.ARPSize
}

func (e *endpoint) WritePacket(r *stack.Route, hdr *buffer.Prependable, payload buffer.View, protocol tcpip.TransportProtocolNumber) error {
	panic("arp.WritePacket TODO")
}

func (e *endpoint) HandlePacket(r *stack.Route, v buffer.View) {
	h := header.ARP(v)
	if !h.IsValid() {
		return
	}

	localAddr := tcpip.Address(h.ProtocolAddressTarget())
	nic := e.stack.CheckLocalAddress(0, localAddr)
	if nic == 0 {
		return // ignore
	}

	// TODO: add HardwareAddressSender/ProtocolAddressSender to ARP cache
	fmt.Printf("TODO add %x/%s to ARP cache\n", h.HardwareAddressSender(), tcpip.Address(h.ProtocolAddressSender()))

	if h.Op() == header.ARPRequest {
		//dst := tcpip.Address(h.ProtocolAddressSender())
		h.SetOp(header.ARPReply)
		copy(h.HardwareAddressSender(), r.LocalLinkAddress[:])
		copy(h.ProtocolAddressSender(), h.ProtocolAddressTarget())
		hdr := buffer.NewPrependable(int(e.linkEP.MaxHeaderLength()))
		e.linkEP.WritePacket(r, &hdr, v, ProtocolNumber)
	}

	//e.dispatcher.DeliverTransportPacket(r, tcpip.TransportProtocolNumber(h.Protocol()), v)
}

type protocol struct{}

func (p *protocol) Number() tcpip.NetworkProtocolNumber { return ProtocolNumber }
func (p *protocol) MinimumPacketSize() int              { return header.ARPSize }

// ParseAddresses implements NetworkProtocol.ParseAddresses.
func (*protocol) ParseAddresses(v buffer.View) (src, dst tcpip.Address) {
	return "", ""
}

func (p *protocol) NewEndpoint(nicid tcpip.NICID, addr tcpip.Address, dispatcher stack.TransportDispatcher, linkEP stack.LinkEndpoint, s *stack.Stack) (stack.NetworkEndpoint, error) {
	return &endpoint{
		nicid:      nicid,
		linkEP:     linkEP,
		dispatcher: dispatcher,
		stack:      s,
	}, nil
}

func init() {
	stack.RegisterNetworkProtocol(ProtocolName, &protocol{})
}
