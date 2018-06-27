package socks

import (
	"fmt"
	"io"
	"net"
)

type socksClient struct {
	conn         *net.TCPConn
	udpConn      *net.UDPConn
	clientConfig *SocksClientConfig
	dataBuf      []byte
}

func NewClient(scc *SocksClientConfig) (*socksClient, error) {
	var (
		client = &socksClient{clientConfig: scc}
		srv    = &net.TCPAddr{IP: net.ParseIP(scc.ServerAddr), Port: scc.ServerPort}
		err    error
	)

	client.conn, err = net.DialTCP("tcp", nil, srv)
	if err != nil {
		return nil, fmt.Errorf("failed connect server, %s", err.Error())
	}

	handshakeRepond, err := client.handshake()
	if err != nil {
		client.conn.Close()
		return nil, err
	}

	switch handshakeRepond {
	case 0xff:
		client.conn.Close()
		return nil, fmt.Errorf("server reject connection")

	case Socks_auth_nobody:
	case Socks_auth_pass:
		if err := client.authUser(); err != nil {
			client.conn.Close()
			return nil, err
		}

	default:
		client.conn.Close()
		return nil, fmt.Errorf("server reject authentication")
	}

	return client, nil
}

func (s *socksClient) handshake() (byte, error) {
	var failure byte = 0xff
	handshakeBuf := []byte{Socks_version, 0x02, Socks_auth_nobody, Socks_auth_pass}
	if _, err := s.conn.Write(handshakeBuf); err != nil {
		s.conn.Close()
		return failure, fmt.Errorf("failed to send first handshake, %s", err.Error())
	}

	handshakeRepond := make([]byte, 2)
	if _, err := io.ReadAtLeast(s.conn, handshakeRepond, len(handshakeRepond)); err != nil {
		return failure, err
	}

	if handshakeRepond[0] != Socks_version {
		return failure, fmt.Errorf("server handshake respond error")
	}

	return handshakeRepond[1], nil
}

func (s *socksClient) authUser() error {
	userLen := len(s.clientConfig.Username)
	passLen := len(s.clientConfig.Password)
	if userLen == 0 || passLen == 0 {
		return fmt.Errorf("user '%s' or pass '%s' is empty", s.clientConfig.Username, s.clientConfig.Password)
	}

	authBuf := make([]byte, 3+userLen+passLen)
	authBuf[0] = 0x01
	authBuf[1] = byte(userLen)
	copy(authBuf[2:], s.clientConfig.Username)
	authBuf[2+userLen] = byte(passLen)
	copy(authBuf[3+userLen:], s.clientConfig.Password)

	if _, err := s.conn.Write(authBuf); err != nil {
		return fmt.Errorf("send authentication failed, %s", err.Error())
	}

	authRepond := make([]byte, 2)
	if _, err := io.ReadAtLeast(s.conn, authRepond, len(authRepond)); err != nil {
		return err
	}

	if authRepond[0] != 0x01 || authRepond[1] != Socks_auth_success {
		return fmt.Errorf("authentication failed")
	}

	return nil
}

func (s *socksClient) buildCmdHeader(cmd byte, atyp byte, addr string, port int) ([]byte, error) {
	var headlen = 6
	switch atyp {
	case Socks_atyp_ipv4:
		headlen = headlen + 4
	case Socks_atyp_fqdn:
		headlen = headlen + 1 + len(addr)
	case Socks_atyp_ipv6:
		fallthrough
	default:
		return nil, fmt.Errorf("not support ATYP")
	}

	head := make([]byte, headlen)
	head[0] = Socks_version
	head[1] = cmd
	head[2] = Socks_RSV
	head[3] = atyp

	if atyp == Socks_atyp_fqdn {
		addrlen, err := int2byte(len(addr))
		if err != nil {
			return nil, err
		}

		head[4] = addrlen
		copy(head[5:], []byte(addr))
	} else {
		ip, err := ip2bytes(addr)
		if err != nil {
			return nil, err
		}
		copy(head[4:], ip)
	}

	pBytes, err := port2bytes(port)
	if err != nil {
		return nil, err
	}

	lastpos := headlen - 2
	copy(head[lastpos:], pBytes)

	return head, nil
}

//////////////////////////////////////////////////////////////////////////
// udp client
//////////////////////////////////////////////////////////////////////////
type socksTcpClient struct {
	socks *socksClient
}

func (s *socksClient) NewTcpClient() *socksTcpClient {
	return &socksTcpClient{socks: s}
}

func (tcp *socksTcpClient) Connect(atyp byte, addr string, port int) error {
	cmd, err := tcp.socks.buildCmdHeader(Socks_cmd_connect, atyp, addr, port)
	if err != nil {
		return err
	}

	if _, err := tcp.socks.conn.Write(cmd); err != nil {
		return err
	}

	// 读取服务器的应答
	rep := make([]byte, 4)
	if _, err := io.ReadAtLeast(tcp.socks.conn, rep, len(rep)); err != nil {
		return err
	}
	if rep[0] != Socks_version {
		return fmt.Errorf("server reply bad head")
	}
	if rep[1] != Socks_cmd_rep_success {
		return fmt.Errorf("server reject connect")
	}
	if rep[2] != Socks_RSV {
		return fmt.Errorf("server reply bad head")
	}

	var bindlen int
	switch rep[3] {
	case Socks_atyp_ipv4:
		bindlen = 6
	case Socks_atyp_fqdn:
		addrlen := make([]byte, 1)
		if _, err := io.ReadAtLeast(tcp.socks.conn, addrlen, len(addrlen)); err != nil {
			return fmt.Errorf("failed to read bnd.addr length")
		}
		bindlen = int(addrlen[0])
	case Socks_atyp_ipv6:
		bindlen = 8
	default:
		return fmt.Errorf("unkown atyp field")
	}

	bind := make([]byte, bindlen)
	if _, err := io.ReadAtLeast(tcp.socks.conn, bind, bindlen); err != nil {
		return fmt.Errorf("failed to read bnd.addr and bnd.port")
	}

	//fmt.Println("=============bnd.addr and bnd.port================")
	//fmt.Printf("ip => %d.%d.%d.%d\n", int(bind[0]), int(bind[1]), int(bind[2]), int(bind[3]))
	//fmt.Printf("port => %d\n", 256*int(bind[4])+int(bind[5]))

	return nil
}

func (tcp *socksTcpClient) Send(data []byte) error {
	if _, err := tcp.socks.conn.Write(data); err != nil {
		return err
	}
	return nil
}

func (tcp *socksTcpClient) Recv() ([]byte, error) {
	data, err := ReadAll(tcp.socks.conn)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (tcp *socksTcpClient) Close() {
	if tcp.socks.conn != nil {
		tcp.socks.conn.Close()
	}
}

//////////////////////////////////////////////////////////////////////////
// udp client
//////////////////////////////////////////////////////////////////////////
type socksUdpClient struct {
	socks *socksClient
	conn  *net.UDPConn
	head  []byte
}

func (s *socksClient) NewUdpClient(atyp byte, raddr string, port int) (*socksUdpClient, error) {
	udp := &socksUdpClient{socks: s}

	remoteIP, remotePort, err := udp.initUDPAssociate("0.0.0.0", 0)
	if err != nil {
		s.conn.Close()
		return nil, err
	}

	udp.conn, err = net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP(remoteIP), Port: remotePort})
	if err != nil {
		s.conn.Close()
		return nil, err
	}

	udp.head, err = udp.buildUdpHeader(atyp, raddr, port)
	if err != nil {
		udp.conn.Close()
		s.conn.Close()
		return nil, err
	}

	return udp, nil
}

func (udp *socksUdpClient) initUDPAssociate(ip string, port int) (remoteIP string, remotePort int, err error) {
	cmd, err := udp.socks.buildCmdHeader(Socks_cmd_udp_associate, Socks_atyp_ipv4, ip, port)
	if err != nil {
		return
	}

	if _, err = udp.socks.conn.Write(cmd); err != nil {
		return
	}

	// 读取服务器的应答
	rep := make([]byte, 4)
	if _, err = io.ReadAtLeast(udp.socks.conn, rep, len(rep)); err != nil {
		return "", 0, err
	}
	if rep[0] != Socks_version {
		return "", 0, fmt.Errorf("server reply bad head")
	}
	if rep[1] != Socks_cmd_rep_success {
		return "", 0, fmt.Errorf("server reject connect")
	}
	if rep[2] != Socks_RSV {
		return "", 0, fmt.Errorf("server reply bad head")
	}

	//fmt.Println("=============server cmd reply head================")
	//fmt.Println(rep)

	var bindlen int
	switch rep[3] {
	case Socks_atyp_ipv4:
		bindlen = 6
	case Socks_atyp_fqdn:
		addrlen := make([]byte, 1)
		if _, err = io.ReadAtLeast(udp.socks.conn, addrlen, len(addrlen)); err != nil {
			return "", 0, fmt.Errorf("failed to read bnd.addr length")
		}
		bindlen = int(addrlen[0])
	case Socks_atyp_ipv6:
		bindlen = 8
	default:
		return "", 0, fmt.Errorf("unkown atyp field")
	}

	bind := make([]byte, bindlen)
	if _, err = io.ReadAtLeast(udp.socks.conn, bind, bindlen); err != nil {
		return "", 0, fmt.Errorf("failed to read bnd.addr and bnd.port")
	}

	remoteIP = fmt.Sprintf("%d.%d.%d.%d", int(bind[0]), int(bind[1]), int(bind[2]), int(bind[3]))
	remotePort = 256*int(bind[4]) + int(bind[5])

	//fmt.Println("=============bnd.addr and bnd.port================")
	//fmt.Printf("ip => %s\n", remoteIP)
	//fmt.Printf("port => %d\n", remotePort)

	return
}

func (udp *socksUdpClient) Sendto(data []byte) error {
	headlen := len(udp.head)
	datalen := len(data)
	entity := make([]byte, headlen+datalen)
	copy(entity, udp.head)
	copy(entity[headlen:], data)

	if _, err := udp.conn.Write(entity); err != nil {
		udp.Close()
		fmt.Println(err.Error())
		return err
	}

	return nil
}

func (udp *socksUdpClient) Recvfrom() ([]byte, error) {
	var (
		buflen = 32 * 1024
		buf    = make([]byte, buflen)
	)

	n, _, err := udp.conn.ReadFromUDP(buf)
	if err != nil {
		return nil, err
	}
	if n < 10 {
		return nil, fmt.Errorf("received data to less")
	}

	var headlen int
	switch buf[3] {
	case Socks_atyp_ipv4:
		headlen = 10
	case Socks_atyp_fqdn:
		addrlen := int(buf[4])
		if n <= addrlen+6 {
			return nil, fmt.Errorf("received data to less")
		}
		headlen = addrlen + 6
	case Socks_atyp_ipv6:
		headlen = 12
	default:
		return nil, fmt.Errorf("receive bad data")
	}

	return buf[headlen:n], nil
}

func (udp *socksUdpClient) Close() error {
	if udp.conn != nil {
		udp.conn.Close()
	}
	if udp.socks.conn != nil {
		udp.socks.conn.Close()
	}
	return nil
}

func (udp *socksUdpClient) buildUdpHeader(atyp byte, addr string, port int) (header []byte, err error) {
	var hlen = 6
	switch atyp {
	case Socks_atyp_ipv4:
		hlen = hlen + 4
	case Socks_atyp_fqdn:
		hlen = hlen + 1 + len(addr)
	case Socks_atyp_ipv6:
		fallthrough
	default:
		return nil, fmt.Errorf("not support ATYP")
	}

	header = make([]byte, hlen)
	header[0] = Socks_RSV
	header[1] = Socks_RSV
	header[2] = 0x00
	header[3] = atyp

	if atyp == Socks_atyp_fqdn {
		addrlen, err := int2byte(len(addr))
		if err != nil {
			return nil, err
		}

		header[4] = addrlen
		copy(header[5:], []byte(addr))
	} else {
		ip, err := ip2bytes(addr)
		if err != nil {
			return nil, err
		}
		copy(header[4:], ip)
	}

	pBytes, err := port2bytes(port)
	if err != nil {
		return nil, err
	}

	lastpos := hlen - 2
	copy(header[lastpos:], pBytes)

	return
}
