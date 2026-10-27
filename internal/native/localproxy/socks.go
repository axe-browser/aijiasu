package localproxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

func (server *Server) serveSOCKS(client *trackedConn, reader *bufio.Reader, deadline time.Time) {
	var greeting [2]byte
	if _, err := io.ReadFull(reader, greeting[:]); err != nil || greeting[0] != 5 {
		return
	}
	methods := make([]byte, int(greeting[1]))
	if _, err := io.ReadFull(reader, methods); err != nil {
		return
	}
	method := byte(0)
	if server.authenticate {
		method = 2
	}
	selected := byte(255)
	for _, candidate := range methods {
		if candidate == method {
			selected = method
		}
	}
	if _, err := client.Write([]byte{5, selected}); err != nil || selected == 255 {
		return
	}
	if method == 2 && !server.socksAuthentication(client, reader) {
		return
	}
	var request [4]byte
	if _, err := io.ReadFull(reader, request[:]); err != nil {
		return
	}
	if request[0] != 5 || request[2] != 0 {
		writeSOCKSReply(client, 1)
		return
	}
	if request[1] != 1 {
		writeSOCKSReply(client, 7) // BIND and UDP ASSOCIATE are not implemented.
		return
	}
	host, ok := readSOCKSHost(reader, request[3])
	if !ok {
		writeSOCKSReply(client, 8)
		return
	}
	var portBytes [2]byte
	if _, err := io.ReadFull(reader, portBytes[:]); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBytes[:])
	if port == 0 {
		writeSOCKSReply(client, 1)
		return
	}
	ctx, cancel := context.WithDeadline(server.ctx, deadline)
	defer cancel()
	upstream, err := server.dial(ctx, net.JoinHostPort(host, strconv.Itoa(int(port))))
	if err != nil {
		writeSOCKSReply(client, 5)
		return
	}
	defer upstream.Close()
	if !writeSOCKSReply(client, 0) {
		return
	}
	if err := client.SetDeadline(time.Time{}); err != nil {
		return
	}
	relay(client, upstream, reader)
}

func (server *Server) socksAuthentication(client net.Conn, reader io.Reader) bool {
	var prefix [2]byte
	if _, err := io.ReadFull(reader, prefix[:]); err != nil {
		return false
	}
	if prefix[0] != 1 || prefix[1] == 0 {
		_, _ = client.Write([]byte{1, 1})
		return false
	}
	username := make([]byte, int(prefix[1]))
	defer clear(username)
	if _, err := io.ReadFull(reader, username); err != nil {
		return false
	}
	var passwordLength [1]byte
	if _, err := io.ReadFull(reader, passwordLength[:]); err != nil {
		return false
	}
	password := make([]byte, int(passwordLength[0]))
	defer clear(password)
	if _, err := io.ReadFull(reader, password); err != nil {
		return false
	}
	valid := len(password) > 0 && server.validCredentials(username, password)
	status := byte(1)
	if valid {
		status = 0
	}
	_, err := client.Write([]byte{1, status})
	return err == nil && valid
}

func readSOCKSHost(reader io.Reader, kind byte) (string, bool) {
	var size int
	switch kind {
	case 1:
		size = net.IPv4len
	case 4:
		size = net.IPv6len
	case 3:
		var length [1]byte
		if _, err := io.ReadFull(reader, length[:]); err != nil || length[0] == 0 {
			return "", false
		}
		size = int(length[0])
	default:
		return "", false
	}
	value := make([]byte, size)
	if _, err := io.ReadFull(reader, value); err != nil {
		return "", false
	}
	if kind == 3 {
		host := string(value)
		return host, validHost(host) && !strings.ContainsAny(host, ":[]")
	}
	return net.IP(value).String(), true
}

func writeSOCKSReply(writer io.Writer, code byte) bool {
	_, err := writer.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
	return err == nil
}
