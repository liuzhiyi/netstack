// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package icmpv6

import (
	"fmt"
	"io"
	"sync"

	"github.com/google/netstack/tcpip"
	"github.com/google/netstack/tcpip/buffer"
	"github.com/google/netstack/tcpip/header"
	"github.com/google/netstack/tcpip/stack"
	"github.com/google/netstack/waiter"
)

const (
	ProtocolName = "icmpv6"

	ProtocolNumber tcpip.TransportProtocolNumber = 58
)

// TODO: ilist generator

type icmpPacket struct {
	icmpPacketEntry
	senderAddress tcpip.FullAddress
	view          buffer.View
}

type protocol struct{}

func (*protocol) Number() tcpip.TransportProtocolNumber { return ProtocolNumber }

func (*protocol) NewEndpoint(stack *stack.Stack, netProto tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, error) {
	return newEndpoint(stack, netProto, waiterQueue), nil
}

func (*protocol) MinimumPacketSize() int {
	return 4
}

func (*protocol) ParsePorts(v buffer.View) (src, dst uint16, err error) {
	h := header.UDP(v)
	return h.SourcePort(), h.DestinationPort(), nil
}

func (*protocol) HandleUnknownDestinationPacket(r *stack.Route, id stack.TransportEndpointID, v buffer.View) {
	fmt.Printf("icmpv6 HandleUnknownDestinationPacket\n")
}

func init() {
	stack.RegisterTransportProtocol(ProtocolName, &protocol{})
}

type endpointState int

const (
	stateInitial endpointState = iota
	stateBound
	stateConnected
	stateClosed
)

type endpoint struct {
	// The following fields are initialized at creation time and do not
	// change throughout the lifetime of the endpoint.
	stack       *stack.Stack
	netProto    tcpip.NetworkProtocolNumber
	waiterQueue *waiter.Queue

	rcvMu      sync.Mutex
	rcvReady   bool
	rcvList    icmpPacketList
	rcvBufSize int
	rcvClosed  bool

	mu        sync.RWMutex
	id        stack.TransportEndpointID
	state     endpointState
	bindNICID tcpip.NICID
	bindAddr  tcpip.Address
	regNICID  tcpip.NICID
}

func newEndpoint(stack *stack.Stack, netProto tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) *endpoint {
	// TODO: Use the send buffer size initialized here.
	return &endpoint{
		stack:       stack,
		netProto:    netProto,
		waiterQueue: waiterQueue,
	}
}

func (e *endpoint) Close() {
}
func (e *endpoint) Read(addr *tcpip.FullAddress) (buffer.View, error) {
	e.rcvMu.Lock()

	if e.rcvList.Empty() {
		err := tcpip.ErrWouldBlock
		if e.rcvClosed {
			err = tcpip.ErrClosedForReceive
		}
		e.rcvMu.Unlock()
		return buffer.View{}, err
	}

	p := e.rcvList.Front()
	e.rcvList.Remove(p)
	e.rcvBufSize -= len(p.view)

	e.rcvMu.Unlock()

	if addr != nil {
		*addr = p.senderAddress
	}

	return p.view, nil
}
func (e *endpoint) Write(v buffer.View, to *tcpip.FullAddress) (uintptr, error) {
	panic("TODO icmpv6.Write")
}
func (e *endpoint) SendMsg(v buffer.View, c tcpip.ControlMessages, to *tcpip.FullAddress) (uintptr, error) {
	// Reject control messages.
	if c != nil {
		// tcpip.ErrInvalidEndpointState turns into syscall.EINVAL.
		return 0, tcpip.ErrInvalidEndpointState
	}
	return e.Write(v, to)
}
func (e *endpoint) Peek(io.Writer) (uintptr, error) {
	return 0, nil
}
func (*endpoint) SetSockOpt(interface{}) error {
	return nil
}
func (e *endpoint) GetSockOpt(opt interface{}) error {
	return tcpip.ErrInvalidEndpointState
}
func (e *endpoint) Connect(addr tcpip.FullAddress) error {
	panic("TODO icmpv6.Connect")
}
func (*endpoint) ConnectEndpoint(tcpip.Endpoint) error {
	return tcpip.ErrInvalidEndpointState
}
func (e *endpoint) Shutdown(flags tcpip.ShutdownFlags) error {
	panic("TODO icmpv6.Shutdown")
}
func (*endpoint) Listen(int) error {
	return tcpip.ErrNotSupported
}
func (*endpoint) Accept() (tcpip.Endpoint, *waiter.Queue, error) {
	return nil, nil, tcpip.ErrNotSupported
}
func (e *endpoint) RecvMsg(addr *tcpip.FullAddress) (buffer.View, tcpip.ControlMessages, error) {
	v, err := e.Read(addr)
	return v, nil, err
}

func (e *endpoint) registerWithStack(nicid tcpip.NICID, id stack.TransportEndpointID) (stack.TransportEndpointID, error) {
	err := e.stack.RegisterTransportEndpoint(nicid, ProtocolNumber, id, e)
	return id, err
}

func (e *endpoint) bindLocked(addr tcpip.FullAddress, commit func() error) error {
	// Don't allow binding once endpoint is not in the initial state
	// anymore.
	if e.state != stateInitial {
		return tcpip.ErrInvalidEndpointState
	}

	if len(addr.Addr) != 0 {
		// A local address was specified, verify that it's valid.
		if e.stack.CheckLocalAddress(addr.NIC, addr.Addr) == 0 {
			return tcpip.ErrBadLocalAddress
		}
	}

	id := stack.TransportEndpointID{LocalAddress: addr.Addr}
	id, err := e.registerWithStack(addr.NIC, id)
	if err != nil {
		return err
	}
	if commit != nil {
		if err := commit(); err != nil {
			// Unregister, the commit failed.
			e.stack.UnregisterTransportEndpoint(addr.NIC, ProtocolNumber, id)
			return err
		}
	}

	e.id = id
	e.regNICID = addr.NIC

	// Mark endpoint as bound.
	e.state = stateBound

	e.rcvMu.Lock()
	e.rcvReady = true
	e.rcvMu.Unlock()

	return nil
}

func (e *endpoint) Bind(addr tcpip.FullAddress, commit func() error) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	err := e.bindLocked(addr, commit)
	if err != nil {
		return err
	}

	e.bindNICID = addr.NIC
	e.bindAddr = addr.Addr

	return nil
}
func (e *endpoint) GetLocalAddress() (tcpip.FullAddress, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return tcpip.FullAddress{
		NIC:  e.regNICID,
		Addr: e.id.LocalAddress,
	}, nil
}
func (e *endpoint) GetRemoteAddress() (tcpip.FullAddress, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.state != stateConnected {
		return tcpip.FullAddress{}, tcpip.ErrInvalidEndpointState
	}

	return tcpip.FullAddress{
		NIC:  e.regNICID,
		Addr: e.id.RemoteAddress,
		Port: e.id.RemotePort,
	}, nil
}
func (e *endpoint) Readiness(mask waiter.EventMask) waiter.EventMask {
	panic("TODO icmpv6.Readiness")
}

func sendICMPv6(r *stack.Route, typ header.ICMPv6Type, code byte, data buffer.View) error {
	hdr := buffer.NewPrependable(header.ICMPv6MinimumSize + int(r.MaxHeaderLength()))

	icmpv6 := header.ICMPv6(hdr.Prepend(header.ICMPv6MinimumSize))

	length := hdr.UsedLength()
	xsum := r.PseudoHeaderChecksum(ProtocolNumber)
	if data != nil {
		length += len(data)
		xsum = header.Checksum(data, xsum)
	}

	icmpv6.SetType(typ)
	icmpv6.SetCode(code)
	icmpv6.SetChecksum(^icmpv6.CalculateChecksum(xsum, length))

	fmt.Printf("send ICMPv6: len(hdr.UsedBytes())=%d\n", len(hdr.UsedBytes()))

	return r.WritePacket(&hdr, data, ProtocolNumber)
}

var OurMAC [6]byte // HACK!

func (e *endpoint) HandlePacket(r *stack.Route, id stack.TransportEndpointID, v buffer.View) {
	h := header.ICMPv6(v)
	fmt.Printf("icmpv6.HandlePacket: len(v)=%d, type=%d, code=%d\n", len(v), h.Type(), h.Code())

	switch h.Type() {
	case header.NeighborSolicitation:
		origv := v
		// TODO: queues and stuff
		v := make(buffer.View, 4+16+2+len(OurMAC))
		v[0] |= 1 << 6 // Solicited flag
		v[0] |= 1 << 5 // Override flag
		copy(v[4:20], origv[8:24])
		v[20] = 2 // Target Link-layer Address
		v[21] = 1
		copy(v[22:], OurMAC[:])
		fmt.Printf("icmpv6 r.LocalAddress=...:%02x%02x\n", r.LocalAddress[14], r.LocalAddress[15])
		fmt.Printf("icmpv6 r.RemoteAddress=...:%02x%02x\n", r.RemoteAddress[14], r.RemoteAddress[15])
		if addr := r.ConcreteAddress(); addr != "" {
			r2 := *r
			r2.LocalAddress = addr
			r = &r2
		}
		if err := sendICMPv6(r, header.NeighborAdvertisements, 0, v); err != nil {
			fmt.Printf("icmpv6 failed to write packet: %v\n", err)
		}
	case header.EchoRequest:
		origv := v
		v := make(buffer.View, len(origv)-4)
		copy(v, origv[4:])
		if addr := r.ConcreteAddress(); addr != "" {
			r2 := *r
			r2.LocalAddress = addr
			r = &r2
		}
		sendICMPv6(r, header.EchoReply, 0, v)
	}
}
