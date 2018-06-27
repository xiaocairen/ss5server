package socks

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

const (
	Socks_version           byte = 0x05
	Socks_RSV               byte = 0x00
	Socks_auth_nobody       byte = 0x00
	Socks_auth_pass         byte = 0x02
	Socks_auth_success      byte = 0x00
	Socks_method_nobody     byte = 0x00
	Socks_method_gssapi     byte = 0x01
	Socks_method_userpass   byte = 0x02
	Socks_method_failure    byte = 0xff
	Socks_cmd_connect       byte = 0x01
	Socks_cmd_bind          byte = 0x02
	Socks_cmd_udp_associate byte = 0x03
	Socks_cmd_rep_success   byte = 0x00
	Socks_cmd_rep_reject    byte = 0x05
	Socks_atyp_ipv4         byte = 0x01
	Socks_atyp_fqdn         byte = 0x03
	Socks_atyp_ipv6         byte = 0x04
)

const (
	Sign_continue         byte = 0x00
	Sign_close_connection byte = 0x0F
)

type SocksServerConfig struct {
	MaxConnections     uint16
	ConnectTimeout     uint8
	ListenIP           string
	ListenPort         uint16
	RequiredAuth       bool
	UserAuthentication UserAuth
}

type SocksClientConfig struct {
	ServerAddr string
	ServerPort int
	Username   string
	Password   string
}

func int2byte(n int) (byte, error) {
	var failure byte = 0x00
	nbuf := bytes.NewBuffer([]byte{})
	if err := binary.Write(nbuf, binary.BigEndian, uint8(n)); err != nil {
		return failure, err
	}

	return nbuf.Bytes()[0], nil
}

func ip2bytes(ipStr string) ([]byte, error) {
	ip := strings.Split(ipStr, ".")
	ipBytes := make([]byte, 4)
	for i, s := range ip {
		p, err := strconv.Atoi(s)
		if err != nil {
			return nil, err
		}
		ipBuf := bytes.NewBuffer([]byte{})
		if err := binary.Write(ipBuf, binary.BigEndian, uint8(p)); err != nil {
			return nil, err
		}
		ipBytes[i] = ipBuf.Bytes()[0]
	}

	return ipBytes, nil
}

func port2bytes(port int) ([]byte, error) {
	portBuf := bytes.NewBuffer([]byte{})
	if err := binary.Write(portBuf, binary.BigEndian, uint16(port)); err != nil {
		return nil, err
	}

	return portBuf.Bytes(), nil
}

func ReadAll(src io.Reader) ([]byte, error) {
	var ret []byte
	for {
		buf := make([]byte, 1500)
		n, err := src.Read(buf)
		if err != nil {
			if n > 0 {
				if ret == nil {
					return buf[:n], nil
				} else {
					for _, b := range buf[:n] {
						ret = append(ret, b)
					}
				}
			}
			break
		}

		if n < 1500 {
			if ret == nil {
				return buf[:n], nil
			} else {
				for _, b := range buf[:n] {
					ret = append(ret, b)
				}
				break
			}
		}

		for _, b := range buf[:n] {
			ret = append(ret, b)
		}
	}

	if ret == nil {
		return nil, fmt.Errorf("read nothing")
	}
	return ret, nil
}

func GetExternalIP() (ip string, err error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil && !strings.Contains(ipnet.IP.String(), "192.168.") {
				ip = ipnet.IP.String()
				break
			}
		}
	}

	return
}

func ParseIPAndPort(addr string) (ip string, port int, err error) {
	IPAndPort := strings.Split(addr, ":")
	size := len(IPAndPort)
	if size < 2 {
		return "", 0, fmt.Errorf("failed parse IP addr %s", addr)
	} else if size == 2 {
		ip = IPAndPort[0]
		port, err = strconv.Atoi(IPAndPort[1])
		if err != nil {
			return
		}
	} else {
		ip = strings.Trim(strings.Join(IPAndPort[:size-1], ":"), "[|]")
		port, err = strconv.Atoi(IPAndPort[size-1])
		if err != nil {
			return
		}
	}

	return
}
