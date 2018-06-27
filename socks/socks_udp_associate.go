package socks

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

type udpData struct {
	raddr *net.UDPAddr
	data  []byte
}

type udpAssociate struct {
	clientIP   string
	clientAddr *net.UDPAddr
	dataChan   chan *udpData
}

func NewUDPAssociateHandler(ip string) *udpAssociate {
	return &udpAssociate{clientIP: ip, dataChan: make(chan *udpData, 100)}
}

func (h *udpAssociate) Run(tcpConn *net.TCPConn, socks *socksServer) error {
	var (
		buf = make([]byte, 2)
		err error
	)

	_, err = io.ReadAtLeast(tcpConn, buf, 2)
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
		dstIP, dstPort, err = socks.readDstIPv4AndPort(tcpConn)
		if err != nil {
			return err
		}
	case Socks_atyp_fqdn:
		dstIP, dstPort, err = socks.readDstDomainAndPort(tcpConn)
		if err != nil {
			return err
		}
	case Socks_atyp_ipv6:
		dstIP, dstPort, err = socks.readDstIPv6AndPort(tcpConn)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("bad atyp field")
	}

	if dstIP != "0.0.0.0" && dstPort != 0 {
		h.clientAddr = &net.UDPAddr{IP: net.ParseIP(dstIP), Port: dstPort}
	}

	udpConn, bindIP, bindPort, err := h.initUdpAgent(socks)
	if err != nil {
		socks.sendCmdReply(tcpConn, Socks_cmd_rep_reject, "0.0.0.0", 0)
		tcpConn.Close()
		if udpConn != nil {
			udpConn.Close()
		}
		return err
	}
	if err := socks.sendCmdReply(tcpConn, Socks_cmd_rep_success, bindIP, bindPort); err != nil {
		tcpConn.Close()
		udpConn.Close()
		return err
	}

	go h.readData(udpConn, tcpConn)
	go h.writeData(udpConn, tcpConn, socks.config.ConnectTimeout)

	return nil
}

func (h *udpAssociate) initUdpAgent(socks *socksServer) (*net.UDPConn, string, int, error) {
	var (
		listenIP string
		err      error
	)
	if socks.config.ListenIP == "" || socks.config.ListenIP == "0.0.0.0" {
		if listenIP, err = GetExternalIP(); err != nil {
			return nil, "", 0, err
		}
	} else {
		listenIP = socks.config.ListenIP
	}

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(listenIP)})
	if err != nil {
		return nil, "", 0, err
	}

	ip, port, err := ParseIPAndPort(conn.LocalAddr().String())
	if err != nil {
		return nil, "", 0, err
	}

	return conn, ip, port, nil
}

func (h *udpAssociate) readData(udpConn *net.UDPConn, tcpConn *net.TCPConn) {
	var (
		buf     = make([]byte, 8*1024)
		headers = make(map[string][]byte)
	)
	for {
		n, raddr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			if strings.Contains(err.Error(), "closed") || strings.Contains(err.Error(), "broken pipe") {
				return
			}
			continue
		}

		if h.clientAddr == nil && raddr.IP.String() == h.clientIP {
			h.clientAddr = raddr
		}
		if n == 0 || h.clientAddr == nil {
			continue
		}

		d := &udpData{}
		if raddr.IP.String() == h.clientIP {
			if n <= 10 || buf[2] != Socks_RSV {
				continue
			}

			ip, port, entity, err := h.getRemoteIPAndPort(buf[:n])
			if err != nil {
				continue
			}

			d.data = make([]byte, len(entity))
			d.raddr = &net.UDPAddr{IP: net.ParseIP(ip), Port: port}
			copy(d.data, entity)

			key := d.raddr.String()
			if _, found := headers[key]; !found {
				hlen := n - len(entity)
				headers[key] = make([]byte, hlen)
				copy(headers[key], buf[:hlen])
			}
		} else {
			header, found := headers[raddr.String()]
			if !found {
				continue
			}

			hlen := len(header)
			d.data = make([]byte, hlen+n)

			copy(d.data, header)
			copy(d.data[hlen:], buf[:n])

			d.raddr = h.clientAddr
		}

		h.dataChan <- d
	}
}

func (h *udpAssociate) writeData(udpConn *net.UDPConn, tcpConn *net.TCPConn, timeout uint8) {
	for {
		select {
		case c := <-h.dataChan:
			_, err := udpConn.WriteToUDP(c.data, c.raddr)
			if err != nil && (strings.Contains(err.Error(), "closed") || strings.Contains(err.Error(), "broken pipe")) {
				tcpConn.Close()
				udpConn.Close()
				return
			}
			// fmt.Printf("==> UDP sendto host %s success, data len = %d\n", d.raddr.String(), n)

		case <-time.After(time.Duration(timeout) * time.Second):
			// fmt.Println("==> UDP closer close udp & tcp connections...")
			tcpConn.Close()
			udpConn.Close()
			return
		}
	}
}

/*
func (h *udpAssociate) transmitData(tcpConn *net.TCPConn, udpConn *net.UDPConn) {
	var buf = make([]byte, 32*1024)
	for {
		n, raddr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			if strings.Contains(err.Error(), "closed") || strings.Contains(err.Error(), "broken pipe") {
				return
			}
			continue
		}

		if h.clientAddr == nil && raddr.IP.String() == h.clientIP {
			h.clientAddr = raddr
		}
		if n == 0 || h.clientAddr == nil {
			continue
		}

		if raddr.IP.String() == h.clientIP {
			h.handleClientData(udpConn, buf[:n], raddr)
		} else {
			h.handleRemoteData(udpConn, tcpConn, buf[:n], raddr)
		}
	}
}

func (h *udpAssociate) handleClientData(conn *net.UDPConn, data []byte, addr *net.UDPAddr) {
	if len(data) < 10 || data[2] != 0x00 {
		return
	}

	remoteIP, remotePort, entity, err := h.getRemoteIPAndPort(data)
	if err != nil {
		return
	}

	remoteAddr := &net.UDPAddr{IP: net.ParseIP(remoteIP), Port: remotePort}
	if _, err := conn.WriteToUDP(entity, remoteAddr); err != nil {
		return
	}
	h.sign <- Sign_continue

	//fmt.Printf("==> UDP sendto server %s success, data len = %d\n", remoteAddr.String(), len(entity))
}

func (h *udpAssociate) handleRemoteData(conn *net.UDPConn, tcpc *net.TCPConn, data []byte, raddr *net.UDPAddr) {
	header, found := h.udpHeaders[raddr.String()]
	if !found {
		return
	}

	var (
		hlen   = len(header)
		dlen   = len(data)
		entity = make([]byte, hlen+dlen)
	)

	copy(entity, header)
	copy(entity[hlen:], data)

	if _, err := conn.WriteToUDP(entity, h.clientAddr); err != nil {
		conn.Close()
		tcpc.Close()
		return
	}
	h.sign <- Sign_continue

	//fmt.Printf("==> UDP sendto client %s success, data len = %d\n", h.clientAddr.String(), len(entity))
}

func (h *udpAssociate) closer(tcpConn *net.TCPConn, udpConn *net.UDPConn, timeout uint8) {
	for {
		select {
		case <-h.sign:
		case <-time.After(time.Duration(timeout) * time.Second):
			//fmt.Println("==> UDP closer close udp & tcp connections...")
			tcpConn.Close()
			udpConn.Close()
			return
		}
	}
}

func (h *udpAssociate) getUDPHeaderBytes(raddr *net.UDPAddr) ([]byte, error) {
	ipBytes, err := ip2bytes(raddr.IP.String())
	if err != nil {
		return nil, err
	}
	portBytes, err := port2bytes(raddr.Port)
	if err != nil {
		return nil, err
	}

	var header = make([]byte, 10)
	header[0] = Socks_RSV       // RSV
	header[1] = Socks_RSV       // RSV
	header[2] = 0x00            // FRAG
	header[3] = Socks_atyp_ipv4 // ATYP
	copy(header[4:], ipBytes)
	copy(header[8:], portBytes)

	if header, found := h.udpHeaders[raddr.String()]; found {
		return header, nil
	} else {
		return nil, fmt.Errorf("not found")
	}
}*/

func (h *udpAssociate) getRemoteIPAndPort(data []byte) (remoteIP string, remotePort int, entity []byte, err error) {
	//var remoteKey string

	switch data[3] {
	case Socks_atyp_ipv4:
		remoteIP, remotePort, err = h.getIPAndPort(data[4:10], true, 0)
		if err != nil {
			return
		}

		entity = data[10:]
		//		remoteKey = remoteIP + ":" + strconv.Itoa(remotePort)
		//		if _, found := h.udpHeaders[remoteKey]; !found {
		//			h.udpHeaders[remoteKey] = make([]byte, 10)
		//			copy(h.udpHeaders[remoteKey], data[:10])
		//		}

	case Socks_atyp_fqdn:
		dlen := int(data[4])
		end := dlen + 7
		if len(data) <= end {
			err = fmt.Errorf("bad data")
			return
		}

		remoteIP, remotePort, err = h.getIPAndPort(data[5:end], false, dlen)
		if err != nil {
			return
		}

		entity = data[end:]
		//		remoteKey = remoteIP + ":" + strconv.Itoa(remotePort)
		//		if _, found := h.udpHeaders[remoteKey]; !found {
		//			h.udpHeaders[remoteKey] = make([]byte, end)
		//			copy(h.udpHeaders[remoteKey], data[:end])
		//		}

	case Socks_atyp_ipv6:
		fallthrough
	default:
		err = fmt.Errorf("not support atyp")
		return
	}

	return
}

func (h *udpAssociate) getIPAndPort(data []byte, IPv4 bool, dlen int) (string, int, error) {
	if IPv4 {
		port := 256*int(data[4]) + int(data[5])
		var ipstr []string
		for _, b := range data[:4] {
			ipstr = append(ipstr, strconv.Itoa(int(b)))
		}

		return strings.Join(ipstr, "."), port, nil
	} else {
		addr, err := net.LookupHost(string(data[:dlen]))
		if err != nil {
			return "", 0, err
		}

		port := 256*int(data[dlen:][0]) + int(data[dlen:][1])

		return addr[0], port, nil
	}
}
