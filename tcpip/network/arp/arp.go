// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package arp

import (
	"fmt"
	"sync"
	"time"

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
	nicid   tcpip.NICID
	linkEP  stack.LinkEndpoint
	handler func(*stack.Route, buffer.View) bool
	stack   *stack.Stack
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

	if h.Op() == header.ARPRequest {
		h.SetOp(header.ARPReply)
		copy(h.HardwareAddressSender(), r.LocalLinkAddress[:])
		copy(h.ProtocolAddressSender(), h.ProtocolAddressTarget())
		hdr := buffer.NewPrependable(int(e.linkEP.MaxHeaderLength()))
		e.linkEP.WritePacket(r, &hdr, v, ProtocolNumber)
	}

	if e.handler != nil {
		e.handler(r, v)
	}
}

type protocol struct{}

func (p *protocol) Number() tcpip.NetworkProtocolNumber { return ProtocolNumber }
func (p *protocol) MinimumPacketSize() int              { return header.ARPSize }

// ParseAddresses implements NetworkProtocol.ParseAddresses.
func (*protocol) ParseAddresses(v buffer.View) (src, dst tcpip.Address) {
	return "", ""
}

func (p *protocol) NewEndpoint(cfg stack.NetworkEndpointConfig) (stack.NetworkEndpoint, error) {
	return &endpoint{
		nicid:   cfg.NICID,
		linkEP:  cfg.Sender,
		handler: cfg.DefaultHandler,
		stack:   cfg.Stack,
	}, nil
}

func (p *protocol) NewLinkAddressLookup(s *stack.Stack, nicID tcpip.NICID, linkEP stack.LinkEndpoint) tcpip.LinkAddressLookupFunc {
	return nil
}

func init() {
	stack.RegisterNetworkProtocol(ProtocolName, &protocol{})
}

type lookup struct {
	stack  *stack.Stack
	linkEP stack.LinkEndpoint

	mu      sync.Mutex
	waiters map[chan tcpip.LinkAddress]tcpip.Address
}

// handler is designed to be used as a closure to SetNetworkProtocolHandler.
func (l *lookup) handler(r *stack.Route, v buffer.View) bool {
	h := header.ARP(v)
	localAddr := tcpip.Address(h.ProtocolAddressTarget())
	nic := l.stack.CheckLocalAddress(0, localAddr)
	fmt.Printf("arp: adding %x/%s to cache\n", h.HardwareAddressSender(), tcpip.Address(h.ProtocolAddressSender()))

	addr := tcpip.Address(h.ProtocolAddressSender())
	linkAddr := tcpip.LinkAddress(h.HardwareAddressSender())
	l.stack.AddLinkAddrCache(nic, addr, linkAddr)

	if h.Op() != header.ARPReply {
		return false
	}

	l.mu.Lock()
	for ch, chAddr := range l.waiters {
		if addr == chAddr {
			select {
			case ch <- linkAddr:
			default:
			}
			delete(l.waiters, ch)
		}
	}
	l.mu.Unlock()

	return false
}

var broadcastMAC = tcpip.LinkAddress([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})

func (l *lookup) lookup(remote, local tcpip.Address) (tcpip.LinkAddress, error) {
	ch := make(chan tcpip.LinkAddress)

	r := &stack.Route{
		RemoteLinkAddress: broadcastMAC,
	}

	hdr := buffer.NewPrependable(int(l.linkEP.MaxHeaderLength()) + header.ARPSize)
	h := header.ARP(hdr.Prepend(header.ARPSize))
	h.SetIPv4OverEthernet()
	h.SetOp(header.ARPRequest)
	copy(h.HardwareAddressSender(), l.linkEP.LinkAddress())
	copy(h.ProtocolAddressSender(), local)
	copy(h.ProtocolAddressTarget(), remote)

	err := l.linkEP.WritePacket(r, &hdr, nil, ProtocolNumber)
	if err != nil {
		return "", err
	}

	select {
	case res := <-ch:
		return res, nil
	case <-time.After(5 * time.Second): // TODO configurable ARP Wait
		l.mu.Lock()
		delete(l.waiters, ch)
		l.mu.Unlock()
		return "", tcpip.ErrTimeout
	}
}

func NewLinkAddressLookup(s *stack.Stack, nicID tcpip.NICID, linkEP stack.LinkEndpoint) tcpip.LinkAddressLookupFunc {
	//localLinkAddr := linkEP.LinkAddress()
	l := &lookup{
		stack:   s,
		linkEP:  linkEP,
		waiters: make(map[chan tcpip.LinkAddress]tcpip.Address),
	}

	s.SetNetworkProtocolHandler(ProtocolNumber, l.handler)
	return l.lookup
}
