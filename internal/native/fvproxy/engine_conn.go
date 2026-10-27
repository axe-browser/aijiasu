package fvproxy

import (
	"crypto/cipher"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

const streamWriteChunkBytes = 32 << 10

type streamConn struct {
	net.Conn
	engine                  *Engine
	rx, tx                  cipher.Stream
	readMu, writeMu         sync.Mutex
	closeOnce               sync.Once
	closeError              error
	stateMu                 sync.Mutex
	readClosed, writeClosed bool
}

func (conn *streamConn) Read(data []byte) (int, error) {
	conn.readMu.Lock()
	defer conn.readMu.Unlock()
	n, err := conn.Conn.Read(data)
	if n > 0 {
		conn.rx.XORKeyStream(data[:n], data[:n])
		conn.touch()
	}
	if err == io.EOF {
		conn.markHalfClosed(true)
	} else if err != nil {
		conn.stateMu.Lock()
		readClosed := conn.readClosed
		conn.stateMu.Unlock()
		if !readClosed {
			conn.Close()
		}
	}
	return n, err
}

func (conn *streamConn) Write(data []byte) (int, error) {
	conn.writeMu.Lock()
	defer conn.writeMu.Unlock()
	conn.stateMu.Lock()
	writeClosed := conn.writeClosed
	conn.stateMu.Unlock()
	if writeClosed {
		return 0, net.ErrClosed
	}
	total := 0
	for len(data) > 0 {
		size := min(len(data), streamWriteChunkBytes)
		encrypted := make([]byte, size)
		conn.tx.XORKeyStream(encrypted, data[:size])
		written := 0
		for written < size {
			n, err := conn.Conn.Write(encrypted[written:])
			if n < 0 || n > size-written {
				conn.Close()
				return total + written, io.ErrShortWrite
			}
			written += n
			if n > 0 {
				conn.touch()
			}
			if err != nil {
				conn.Close()
				return total + written, err
			}
			if n == 0 {
				conn.Close()
				return total + written, io.ErrNoProgress
			}
		}
		total += size
		data = data[size:]
	}
	return total, nil
}

func (conn *streamConn) Close() error {
	conn.closeOnce.Do(func() {
		conn.closeError = conn.Conn.Close()
		conn.engine.mu.Lock()
		delete(conn.engine.connections, conn)
		conn.engine.mu.Unlock()
	})
	return conn.closeError
}

func (conn *streamConn) touch() {
	conn.engine.mu.Lock()
	if conn.engine.authenticated {
		conn.engine.lastAlive = time.Now()
	}
	conn.engine.mu.Unlock()
}

func (conn *streamConn) CloseWrite() error {
	conn.writeMu.Lock()
	defer conn.writeMu.Unlock()
	conn.stateMu.Lock()
	closed := conn.writeClosed
	conn.stateMu.Unlock()
	if closed {
		return nil
	}
	writer, ok := conn.Conn.(interface{ CloseWrite() error })
	if !ok {
		return errors.ErrUnsupported
	}
	if err := writer.CloseWrite(); err != nil {
		return err
	}
	conn.markHalfClosed(false)
	return nil
}

func (conn *streamConn) CloseRead() error {
	reader, ok := conn.Conn.(interface{ CloseRead() error })
	if !ok {
		return errors.ErrUnsupported
	}
	conn.markHalfClosed(true)
	return reader.CloseRead()
}

func (conn *streamConn) markHalfClosed(read bool) {
	conn.stateMu.Lock()
	if read {
		conn.readClosed = true
	} else {
		conn.writeClosed = true
	}
	finished := conn.readClosed && conn.writeClosed
	conn.stateMu.Unlock()
	if finished {
		conn.Close()
	}
}
