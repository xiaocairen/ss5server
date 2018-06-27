package socks

import (
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

type tcpConnect struct {
	clientIP string
	sign     chan byte
}

func NewConnectHandler(ip string) *tcpConnect {
	return &tcpConnect{clientIP: ip, sign: make(chan byte, 1024)}
}

func (h *tcpConnect) Run(clientConn *net.TCPConn, socks *socksServer) error {
	var (
		buf = make([]byte, 2)
		err error
	)

	_, err = io.ReadAtLeast(clientConn, buf, 2)
	if err != nil {
		return err
	}
	if buf[0] != Socks_RSV {
		return fmt.Errorf("bad request data")
	}

	var (
		dstIP   string
		dstPort int
	)
	switch buf[1] {
	case Socks_atyp_ipv4:
		dstIP, dstPort, err = socks.readDstIPv4AndPort(clientConn)
		if err != nil {
			return err
		}
	case Socks_atyp_fqdn:
		dstIP, dstPort, err = socks.readDstDomainAndPort(clientConn)
		if err != nil {
			return err
		}
	case Socks_atyp_ipv6:
		dstIP, dstPort, err = socks.readDstIPv6AndPort(clientConn)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("bad atyp field")
	}

	remoteConn, err := net.DialTCP("tcp", nil, &net.TCPAddr{IP: net.ParseIP(dstIP), Port: dstPort})
	if err != nil {
		socks.sendCmdReply(clientConn, Socks_cmd_rep_reject, "0.0.0.0", 0)
		return err
	}
	if err := socks.sendCmdReply(clientConn, Socks_cmd_rep_success, dstIP, dstPort); err != nil {
		return err
	}

	go h.transmitData(clientConn, remoteConn)
	go h.transmitData(remoteConn, clientConn)
	go h.closer(clientConn, remoteConn, socks.config.ConnectTimeout)

	return nil
}

func (h *tcpConnect) transmitData(dst *net.TCPConn, src *net.TCPConn) {
	var buf = make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, err := dst.Write(buf[:n]); err != nil {
				src.Close()
				dst.Close()
				return
			}
			h.sign <- Sign_continue

			//fmt.Printf("==> TCP write to host %s success, data len = %d\n", dst.RemoteAddr().String(), n)
		}

		if err != nil {
			if err == io.EOF || strings.Contains(err.Error(), "broken pipe") || strings.Contains(err.Error(), "closed") {
				dst.Close()
				src.Close()
				return
			}
			continue
		}
	}
}

func (h *tcpConnect) closer(client *net.TCPConn, remote *net.TCPConn, timeout uint8) {
	for {
		select {
		case <-h.sign:
		case <-time.After(time.Duration(timeout) * time.Second):
			//fmt.Println("==> TCP closer close tcp connections...")
			client.Close()
			remote.Close()
			return
		}
	}
}
