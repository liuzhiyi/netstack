// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stack

import (
	"time"

	"github.com/google/netstack/tcpip"
	"github.com/google/netstack/tcpip/buffer"
	"github.com/google/netstack/tcpip/header"
)

// Route represents a route through the networking stack to a given destination.
type Route struct {
	// RemoteAddress is the final destination of the route.
	RemoteAddress tcpip.Address

	// RemoteLinkAddress is the link-layer (MAC) address of the
	// final destination of the route.
	RemoteLinkAddress tcpip.LinkAddress

	// LocalAddress is the local address where the route starts.
	LocalAddress tcpip.Address

	// LocalLinkAddress is the link-layer (MAC) address of the
	// where the route starts.
	LocalLinkAddress tcpip.LinkAddress

	// NextHop is the next node in the path to the destination.
	NextHop tcpip.Address

	// NetProto is the network-layer protocol.
	NetProto tcpip.NetworkProtocolNumber

	// ref a reference to the network endpoint through which the route
	// starts.
	ref *referencedNetworkEndpoint
}

// NICID returns the id of the NIC from which this route originates.
func (r *Route) NICID() tcpip.NICID {
	return r.ref.ep.NICID()
}

// MaxHeaderLength forwards the call to the network endpoint's implementation.
func (r *Route) MaxHeaderLength() uint16 {
	return r.ref.ep.MaxHeaderLength()
}

// PseudoHeaderChecksum forwards the call to the network endpoint's
// implementation.
func (r *Route) PseudoHeaderChecksum(protocol tcpip.TransportProtocolNumber) uint16 {
	return header.PseudoHeaderChecksum(protocol, r.LocalAddress, r.RemoteAddress)
}

// WritePacket writes the packet through the given route.
func (r *Route) WritePacket(hdr *buffer.Prependable, payload buffer.View, protocol tcpip.TransportProtocolNumber) error {
	return r.ref.ep.WritePacket(r, hdr, payload, protocol)
}

// MTU returns the MTU of the underlying network endpoint.
func (r *Route) MTU() uint32 {
	return r.ref.ep.MTU()
}

// Release frees all resources associated with the route.
func (r *Route) Release() {
	if r.ref != nil {
		r.ref.decRef()
		r.ref = nil
	}
}

// Clone Clone a route such that the original one can be released and the new
// one will remain valid.
func (r *Route) Clone() Route {
	r.ref.incRef()
	return *r
}

// FindLinkAddr looks up the remote link address in the link address cache.
// If it cannot find the link address in the cache, it sends
func (r *Route) FindLinkAddr(blocking bool) error {
	nic := r.ref.nic

	nic.mu.RLock()
	// TODO: this is already in FindRoute, skip it here?
	if entry, found := nic.linkAddrCache[r.RemoteAddress]; found {
		r.RemoteLinkAddress = entry.linkAddr
		nic.mu.RUnlock()
		return nil
	}
	if !blocking {
		nic.mu.RUnlock()
		return tcpip.ErrWouldBlock
	}
	fn := nic.linkAddrLookup[r.ref.protocol]
	nic.mu.RUnlock()

	if fn == nil {
		return tcpip.ErrNoRoute
	}
	linkAddr, err := fn(r.RemoteAddress, r.LocalAddress)
	if err != nil {
		return err
	}
	r.RemoteLinkAddress = linkAddr

	nic.mu.Lock()
	nic.linkAddrCache[r.RemoteAddress] = linkAddrEntry{
		linkAddr: linkAddr,
		creation: time.Now(),
	}
	nic.mu.Unlock()
	return nil
}
