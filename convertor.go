package main

import (
	"fmt"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
	"log"
	"net"
	"time"
)

type Convertor struct {
	stack        *stack.Stack
	linkEP       *tunLinkEndpoint
	tunWriteFunc func([]byte) (int, error)
	closed       bool
}

func NewConvertor(tunWriteFunc func([]byte) (int, error)) *Convertor {
	c := &Convertor{
		tunWriteFunc: tunWriteFunc,
	}

	// 初始化 stack
	c.stack = stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})

	// 创建虚拟网卡
	c.linkEP = &tunLinkEndpoint{
		tunWrite: tunWriteFunc,
		Endpoint: channel.New(65536, 1500, ""),
	}

	c.stack.CreateNICWithOptions(1, c.linkEP, stack.NICOptions{
		Disabled: false,
		QDisc:    nil,
	})

	c.stack.AddProtocolAddress(
		1,
		tcpip.ProtocolAddress{
			Protocol: ipv4.ProtocolNumber,
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   tcpip.AddrFrom4([4]byte{0x0a, 0, 0, 1}),
				PrefixLen: 8, // /24 子网掩码
			},
		},
		stack.AddressProperties{PEB: stack.CanBePrimaryEndpoint},
	)

	c.stack.SetPromiscuousMode(1, true)
	c.stack.SetSpoofing(1, true)

	c.stack.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: 1},
	})

	return c
}

func (c *Convertor) SendBytes(buf []byte) {
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: 0,
		Payload:            buffer.MakeWithData(buf),
	})

	c.linkEP.InjectInbound(ipv4.ProtocolNumber, pkt)
}

func (c *Convertor) Close() {
	if c.closed {
		return
	}
	if debug {
		log.Println("[Convertor] closing...")
	}
	c.closed = true

	// 关闭 linkEP，释放底层 channel
	if c.linkEP != nil && c.linkEP.Endpoint != nil {
		c.linkEP.Endpoint.Close()
	}

	_ = c.stack.RemoveNIC(1)
}

func (c *Convertor) StartTCPForwarder(handle func(net.Conn, *stack.TransportEndpointID)) {
	log.Println("StartTCPForwarder")
	const defaultWndSize = 0
	const maxConnAttempts = 2 << 10

	tcpForwarder := tcp.NewForwarder(c.stack, defaultWndSize, maxConnAttempts,
		func(r *tcp.ForwarderRequest) {
			var (
				wq  waiter.Queue
				ep  tcpip.Endpoint
				err tcpip.Error
				id  = r.ID()
			)
			defer func() {
				if err != nil {
					fmt.Printf("forward tcp request: %s:%d->%s:%d: %v\n",
						id.RemoteAddress, id.RemotePort, id.LocalAddress, id.LocalPort, err)
				}
			}()

			ep, err = r.CreateEndpoint(&wq)
			if err != nil {
				log.Println(err)
				r.Complete(true) // RST
				return
			}
			defer r.Complete(false)

			// 可选设置 socket options
			_ = setSocketOptions(c.stack, ep)

			conn := gonet.NewTCPConn(&wq, ep)
			handle(conn, &id)
		})

	c.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)
}

func setSocketOptions(s *stack.Stack, ep tcpip.Endpoint) tcpip.Error {
	{ /* TCP keepalive options */
		ep.SocketOptions().SetKeepAlive(true)

		idle := tcpip.KeepaliveIdleOption(60 * time.Second)
		if err := ep.SetSockOpt(&idle); err != nil {
			return err
		}

		interval := tcpip.KeepaliveIntervalOption(30 * time.Second)
		if err := ep.SetSockOpt(&interval); err != nil {
			return err
		}

		if err := ep.SetSockOptInt(tcpip.KeepaliveCountOption, 9); err != nil {
			return err
		}
	}
	{ /* TCP recv/send buffer size */
		var ss tcpip.TCPSendBufferSizeRangeOption
		if err := s.TransportProtocolOption(header.TCPProtocolNumber, &ss); err == nil {
			ep.SocketOptions().SetSendBufferSize(int64(ss.Default), false)
		}

		var rs tcpip.TCPReceiveBufferSizeRangeOption
		if err := s.TransportProtocolOption(header.TCPProtocolNumber, &rs); err == nil {
			ep.SocketOptions().SetReceiveBufferSize(int64(rs.Default), false)
		}
	}
	return nil
}

type tunLinkEndpoint struct {
	tunWrite func([]byte) (int, error)
	*channel.Endpoint
}

func (e *tunLinkEndpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	n := 0
	for _, pkt := range pkts.AsSlice() {
		buf := pkt.ToBuffer()
		data := buf.Flatten()
		if len(data) == 0 {
			buf.Release()
			continue
		}
		_, err := e.tunWrite(data)
		if err != nil {
			log.Println(err)
			buf.Release()
			return n, nil
		}
		n++
		buf.Release()
	}
	return n, nil
}
