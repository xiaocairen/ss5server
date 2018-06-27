package socks

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
)

type httpProxy struct {
	clientConn *net.TCPConn
	remoteConn *net.TCPConn
}

func (h *httpProxy) run() error {
	if h.clientConn == nil || h.remoteConn == nil {
		return fmt.Errorf("net.TCPConn is nil")
	}

	go h.transmitData()
	return nil
}

func (h *httpProxy) transmitData() {
	data, err := ReadAll(h.clientConn)
	if err != nil {
		return
	}

	_, err = h.remoteConn.Write(data)
	if err != nil {
		return
	}

	bufReader := bufio.NewReader(h.remoteConn)

	var (
		html          = ""
		chunked       bool
		contentLength int
		isImage       bool
	)
	reg, _ := regexp.Compile(`Content\-Length:\s*(\d+)`)
	for {
		buf, err := bufReader.ReadString('\n')
		if err != nil {
			return
		}

		if !chunked && strings.Contains(buf, "Transfer-Encoding") && strings.Contains(buf, "chunked") {
			chunked = true
		}

		if strings.Contains(buf, "Content-Type") && strings.Contains(buf, "image/") {
			isImage = true
		}

		if contentLength == 0 && strings.Contains(buf, "Content-Length") {
			find := reg.FindStringSubmatch(buf)
			if len(find) == 2 {
				contentLength, _ = strconv.Atoi(find[1])
			}
		}

		html += buf
		if buf == "\r\n" {
			break
		}
	}

	if !chunked && contentLength == 0 {
		return
	}

	if chunked {
		for {
			chunkline, err := bufReader.ReadString('\n')
			if err != nil {
				return
			}

			chunklen, _ := strconv.ParseInt(strings.TrimSpace(chunkline), 16, 64)
			html += chunkline
			if chunklen == 0 {
				break
			}

			var rl int64 = 0
			for {
				line, err := bufReader.ReadString('\n')
				if err != nil {
					return
				}

				html += line
				rl += int64(len(line))
				if rl >= chunklen {
					break
				}
			}
		}
	} else if contentLength > 0 {
		var rl int = 0
		if isImage {
			imgData := make([]byte, contentLength)
			for i := 0; i < contentLength; i++ {
				b, e := bufReader.ReadByte()
				if e != nil {
					if e == io.EOF {
						break
					}
					return
				}
				imgData[i] = b
			}

			html += string(imgData)
		} else {
			for {
				line, err := bufReader.ReadString('\n')
				if err != nil {
					return
				}

				html += line
				rl += len(line)
				if rl >= contentLength {
					break
				}
			}
		}
	} else {
		fmt.Printf("==> not content length=\n")
		data, err := ReadAll(h.remoteConn)
		if err != nil {
			return
		}

		html += string(data)
	}

	n, _ := h.clientConn.Write([]byte(html))
	h.clientConn.Close()
	h.remoteConn.Close()

	fmt.Printf("==> transmit http data length=%d\n", n)
}
