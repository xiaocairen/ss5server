package socks

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

type UserAuth interface {
	Authentication(user string, pass string) bool
}

type socksServer struct {
	listener *net.TCPListener
	config   *SocksServerConfig
}

func NewServer(ssc *SocksServerConfig) (*socksServer, error) {
	var (
		server = &socksServer{config: ssc}
		addr   = &net.TCPAddr{IP: net.ParseIP(ssc.ListenIP), Port: int(ssc.ListenPort)}
		err    error
	)

	server.listener, err = net.ListenTCP("tcp", addr)
	if err != nil {
		return nil, err
	}

	return server, nil
}

func (s *socksServer) Run() {
	for {
		conn, err := s.listener.AcceptTCP()
		if err != nil {
			if conn != nil {
				conn.Close()
			}
			continue
		}
		go s.handleConnection(conn)
	}
}

func (s *socksServer) handleConnection(conn *net.TCPConn) {
	IP, _, err := ParseIPAndPort(conn.RemoteAddr().String())
	if err != nil {
		return
	}

	method, err := s.handshake(conn)
	if err != nil {
		conn.Write([]byte{Socks_version, Socks_method_failure})
		conn.Close()
		return
	}

	switch method {
	case Socks_method_nobody, Socks_method_userpass:
		n, err := conn.Write([]byte{Socks_version, method})
		if err != nil || n != 2 {
			conn.Close()
			return
		}
	case Socks_method_failure:
		fallthrough
	default:
		conn.Write([]byte{Socks_version, Socks_method_failure})
		conn.Close()
		return
	}

	if s.config.RequiredAuth {
		if err := s.authUser(conn); err != nil {
			conn.Write([]byte{0x01, 0xff})
			conn.Close()
			return
		} else {
			n, err := conn.Write([]byte{0x01, Socks_auth_success})
			if err != nil || n != 2 {
				conn.Close()
				return
			}
		}
	}

	if err := s.respondAgent(conn, IP); err != nil {
		conn.Close()
	}
}

func (s *socksServer) handshake(conn *net.TCPConn) (byte, error) {
	var (
		buf = make([]byte, 2)
		err error
	)

	// read socks version and methods
	_, err = io.ReadAtLeast(conn, buf, 2)
	if err != nil {
		return Socks_method_failure, err
	}
	if buf[0] != Socks_version {
		return Socks_method_failure, fmt.Errorf("socks version error ver:%d", buf[0])
	}

	// read nmethod
	var (
		nmethod = int(buf[1])
		methods = make([]byte, nmethod)
	)
	_, err = io.ReadAtLeast(conn, methods, nmethod)
	if err != nil {
		return Socks_method_failure, err
	}

	if s.config.RequiredAuth {
		for _, m := range methods {
			if m == Socks_method_userpass {
				return Socks_method_userpass, nil
			}
		}
	} else {
		for _, m := range methods {
			if m == Socks_method_nobody {
				return Socks_method_nobody, nil
			}
		}
	}

	return Socks_method_failure, nil
}

func (s *socksServer) authUser(conn *net.TCPConn) error {
	var (
		max = 1
		buf = make([]byte, max)
		err error
	)

	// 1. read first byte 0x01
	_, err = io.ReadAtLeast(conn, buf, max)
	if err != nil {
		return err
	}
	if buf[0] != 0x01 {
		return fmt.Errorf("bad authentication data")
	}

	// 2. read username length
	_, err = io.ReadAtLeast(conn, buf, max)
	if err != nil {
		return err
	}

	// 3. read username
	var (
		userlen  = int(buf[0])
		username = make([]byte, userlen)
	)
	_, err = io.ReadAtLeast(conn, username, userlen)
	if err != nil {
		return err
	}

	// 4. read password length
	_, err = io.ReadAtLeast(conn, buf, max)
	if err != nil {
		return err
	}

	// 5. read password
	var (
		passlen  = int(buf[0])
		password = make([]byte, passlen)
	)
	_, err = io.ReadAtLeast(conn, password, passlen)
	if err != nil {
		return err
	}

	// 6. auth user password
	if s.config.UserAuthentication == nil {
		return fmt.Errorf("not found user auth func")
	}

	if !s.config.UserAuthentication.Authentication(string(username), string(password)) {
		return fmt.Errorf("authentication failed")
	}

	return nil
}

func (s *socksServer) respondAgent(conn *net.TCPConn, clientIP string) error {
	var (
		buf = make([]byte, 2)
		err error
	)

	// 1. read version and cmd
	_, err = io.ReadAtLeast(conn, buf, 2)
	if err != nil {
		return err
	}
	if buf[0] != Socks_version {
		return fmt.Errorf("bad version")
	}

	switch buf[1] {
	case Socks_cmd_connect:
		return NewConnectHandler(clientIP).Run(conn, s)
	case Socks_cmd_udp_associate:
		return NewUDPAssociateHandler(clientIP).Run(conn, s)
	case Socks_cmd_bind:
		fallthrough
	default:
		return fmt.Errorf("not support cmd type")
	}
}

func (s *socksServer) readDstIPv4AndPort(conn *net.TCPConn) (string, int, error) {
	var buf = make([]byte, 6)
	_, err := io.ReadAtLeast(conn, buf, len(buf))
	if err != nil {
		return "", 0, err
	}

	port := 256*int(buf[4]) + int(buf[5])
	var ipstr []string
	for _, b := range buf[:4] {
		ipstr = append(ipstr, strconv.Itoa(int(b)))
	}

	return strings.Join(ipstr, "."), port, nil
}

func (s *socksServer) readDstDomainAndPort(conn *net.TCPConn) (string, int, error) {
	var (
		buf = make([]byte, 1)
		pt  = make([]byte, 2)
		err error
	)

	// read domain length
	_, err = io.ReadAtLeast(conn, buf, 1)
	if err != nil {
		return "", 0, err
	}

	var (
		domainLen = int(buf[0])
		domain    = make([]byte, domainLen)
	)

	// read domain
	_, err = io.ReadAtLeast(conn, domain, domainLen)
	if err != nil {
		return "", 0, err
	}

	// read port
	_, err = io.ReadAtLeast(conn, pt, 2)
	if err != nil {
		return "", 0, err
	}

	// parse domain to ip
	addr, err := net.LookupHost(string(domain))
	if err != nil {
		return "", 0, err
	}

	port := 256*int(pt[0]) + int(pt[1])

	return addr[0], port, nil
}

func (s *socksServer) readDstIPv6AndPort(conn *net.TCPConn) (string, int, error) {
	return "", 0, fmt.Errorf("not support ipv6")
}

func (s *socksServer) sendCmdReply(conn *net.TCPConn, rep byte, ip string, port int) error {
	ipBytes, _ := ip2bytes(ip)
	portBytes, _ := port2bytes(port)

	reply := make([]byte, 10)
	reply[0] = Socks_version
	reply[1] = rep
	reply[2] = Socks_RSV
	reply[3] = Socks_atyp_ipv4
	copy(reply[4:], ipBytes)
	copy(reply[8:], portBytes)

	if _, err := conn.Write(reply); err != nil {
		return err
	}
	return nil
}
