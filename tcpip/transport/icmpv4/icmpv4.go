// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package icmpv4

import (
	"fmt"
	"io"
	"sync"

	"github.com/google/netstack/tcpip"
	"github.com/google/netstack/tcpip/buffer"
	"github.com/google/netstack/tcpip/header"
	"github.com/google/netstack/tcpip/network/ipv4"
	"github.com/google/netstack/tcpip/stack"
	"github.com/google/netstack/waiter"
)

const (
	ProtocolName = "icmpv4"

	ProtocolNumber tcpip.TransportProtocolNumber = header.ICMPv4ProtocolNumber
)

type icmpPacket struct {
	icmpPacketEntry
	route *stack.Route
	view  buffer.View
}

type protocol struct{}

func (*protocol) Number() tcpip.TransportProtocolNumber { return ProtocolNumber }

func (*protocol) NewEndpoint(stack *stack.Stack, netProto tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, error) {
	return newEndpoint(stack, netProto, waiterQueue), nil
}

func (*protocol) MinimumPacketSize() int {
	return header.ICMPv4MinimumSize
}

func (*protocol) ParsePorts(v buffer.View) (src, dst uint16, err error) {
	return 0, 0, nil
}

func (*protocol) HandleUnknownDestinationPacket(r *stack.Route, id stack.TransportEndpointID, v buffer.View) {
	fmt.Printf("icmpv4 HandleUnknownDestinationPacket\n")
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

	rcvMu         sync.Mutex
	rcvReady      bool
	rcvList       icmpPacketList
	rcvBufSizeMax int
	rcvBufSize    int
	rcvClosed     bool

	mu        sync.RWMutex
	id        stack.TransportEndpointID
	state     endpointState
	bindNICID tcpip.NICID
	bindAddr  tcpip.Address
	regNICID  tcpip.NICID
	route     stack.Route
}

func newEndpoint(stack *stack.Stack, netProto tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) *endpoint {
	// TODO: Use the send buffer size initialized here.
	return &endpoint{
		stack:         stack,
		netProto:      netProto,
		waiterQueue:   waiterQueue,
		rcvBufSizeMax: 8 * 1024,
	}
}

func (e *endpoint) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()

	switch e.state {
	case stateBound, stateConnected:
		e.stack.UnregisterTransportBroadcastEndpoint(e.regNICID, ProtocolNumber, e)
	}

	// Close the receive list and drain it.
	e.rcvMu.Lock()
	e.rcvClosed = true
	e.rcvBufSize = 0
	for !e.rcvList.Empty() {
		p := e.rcvList.Front()
		e.rcvList.Remove(p)
	}
	e.rcvMu.Unlock()

	e.route.Release()
	e.state = stateClosed
}

func (e *endpoint) Read(addr *tcpip.FullAddress) (buffer.View, error) {
	return nil, tcpip.ErrNotSupported
}

func (e *endpoint) Write(v buffer.View, to *tcpip.FullAddress) (uintptr, error) {
	return 0, tcpip.ErrNotSupported
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
	e.mu.Lock()
	defer e.mu.Unlock()

	nicid := addr.NIC
	switch e.state {
	case stateBound:
		if e.bindNICID == 0 {
			break
		}
		if nicid != 0 && nicid != e.bindNICID {
			return tcpip.ErrInvalidEndpointState
		}
		nicid = e.bindNICID
	case stateInitial:
	case stateConnected:
		return tcpip.ErrAlreadyConnected
	default:
		return tcpip.ErrInvalidEndpointState
	}

	r, err := e.stack.FindRoute(nicid, e.id.LocalAddress, addr.Addr, e.netProto)
	if err != nil {
		return err
	}
	defer r.Release()

	// TODO introduce stateConnecting, do this off the goroutine:

	e.id.LocalAddress = r.LocalAddress
	e.id.RemoteAddress = addr.Addr

	if _, err = e.registerWithStack(nicid, e.id); err != nil {
		return err
	}

	e.state = stateConnected
	e.route = r.Clone()
	e.bindNICID = nicid

	e.rcvMu.Lock()
	e.rcvReady = true
	e.rcvMu.Unlock()

	return nil
}

func (*endpoint) ConnectEndpoint(tcpip.Endpoint) error {
	return tcpip.ErrInvalidEndpointState
}
func (e *endpoint) Shutdown(flags tcpip.ShutdownFlags) error {
	panic("TODO icmpv4.Shutdown")
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
	// TODO remove id param
	err := e.stack.RegisterTransportBroadcastEndpoint(nicid, ProtocolNumber, e)
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
			e.stack.UnregisterTransportBroadcastEndpoint(addr.NIC, ProtocolNumber, e)
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
	panic("TODO icmpv4.Readiness")
}

func sendICMPv4(r *stack.Route, typ header.ICMPv4Type, code byte, data buffer.View) error {
	hdr := buffer.NewPrependable(header.ICMPv4MinimumSize + int(r.MaxHeaderLength()))

	icmpv4 := header.ICMPv4(hdr.Prepend(header.ICMPv4MinimumSize))
	icmpv4.SetType(typ)
	icmpv4.SetCode(code)
	icmpv4.SetChecksum(^header.Checksum(icmpv4, header.Checksum(data, 0)))

	// TODO: instead of returning an ignored error, collect a stat
	return r.WritePacket(&hdr, data, ProtocolNumber)
}

func (e *endpoint) HandlePacket(r *stack.Route, id stack.TransportEndpointID, v buffer.View) {
	e.rcvMu.Lock()
	if !e.rcvReady || e.rcvClosed || e.rcvBufSize >= e.rcvBufSizeMax {
		// Drop packet if our buffer is currently full.
		e.rcvMu.Unlock()
		return
	}
	wasEmpty := e.rcvBufSize == 0
	e.rcvList.PushBack(&icmpPacket{
		route: r,
		view:  v,
	})
	e.rcvBufSize += len(v)
	e.rcvMu.Unlock()

	if wasEmpty {
		e.waiterQueue.Notify(waiter.EventIn)
	}
}

func process(p *icmpPacket) {
	r := p.route
	v := p.view
	h := header.ICMPv4(v)
	fmt.Printf("icmpv4.HandlePacket: len(v)=%d, type=%d, code=%d\n", len(v), h.Type(), h.Code())

	switch h.Type() {
	case header.ICMPv4Echo:
		sendICMPv4(r, header.ICMPv4EchoReply, 0, v[4:])
	case header.ICMPv4EchoReply:
		fmt.Printf("\tgot header.ICMPv4EchoReply\n")
	}
}

func Process(s *stack.Stack) error {
	var wq waiter.Queue
	ep, err := s.NewEndpoint(ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if err != nil {
		return err
	}
	s.SetTransportProtocolHandler(ProtocolNumber, func(r *stack.Route, id stack.TransportEndpointID, v buffer.View) bool {
		ep.(stack.TransportEndpoint).HandlePacket(r, id, v)
		return true
	})

	defer ep.Close()

	if err := ep.Bind(tcpip.FullAddress{0, "", 0}, nil); err != nil {
		return err
	}

	waitEntry, notifyCh := waiter.NewChannelEntry(nil)
	wq.EventRegister(&waitEntry, waiter.EventIn)
	defer wq.EventUnregister(&waitEntry)

	e := ep.(*endpoint)
	for {
		e.rcvMu.Lock()
		if e.rcvList.Empty() {
			e.rcvMu.Unlock()
			if e.rcvClosed {
				return tcpip.ErrClosedForReceive
			}
			<-notifyCh
			continue
		}
		p := e.rcvList.Front()
		e.rcvList.Remove(p)
		e.rcvBufSize -= len(p.view)
		e.rcvMu.Unlock()

		process(p)
	}
}

func Ping(ep tcpip.Endpoint) {
	e := ep.(*endpoint)

	v := buffer.NewView(4)
	v[0] = 42 // Identifier
	v[1] = 42 // Identifier
	v[2] = 0
	v[3] = 0 // Seq num

	sendICMPv4(&e.route, header.ICMPv4Echo, 0, v)
}
