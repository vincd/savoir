package tds

import (
	"fmt"
	"net"
	"time"
)

// is there an other way? I cannot find something like bio_read/bio_write in Python
// Implement interface `Conn` from net/net.go
type dummyConn struct {
	c           net.Conn
	buf         []byte
	sendWithTls bool
}

func (c *dummyConn) Read(b []byte) (int, error) {
	if c.buf != nil {
		copy(b, c.buf)
		if len(b) > len(c.buf) {
			n := len(c.buf)
			c.buf = nil
			return n, nil
		} else {
			c.buf = c.buf[len(b):]
			return len(b), nil
		}
	}

	buf := make([]byte, 32763)
	_, err := c.c.Read(buf)
	if err != nil {
		return 0, err
	}

	p, err := NewTdsPacketWithBytes(buf)
	if err != nil {
		return 0, err
	}

	copy(b, p.Data)
	if len(b) < len(p.Data) {
		c.buf = p.Data[len(b):]
	}

	return len(b), nil
}

func (c *dummyConn) Write(b []byte) (int, error) {
	if !c.sendWithTls {
		return c.c.Write(b)
	}

	p := &TdsPacket{
		Type:     TDS_PRE_LOGIN,
		Status:   TDS_STATUS_EOM,
		Length:   uint16(8 + len(b)),
		SPID:     0,
		PacketID: 0,
		Window:   0,
		Data:     b,
	}

	newData := p.Bytes()
	n, err := c.c.Write(newData)
	if err != nil {
		return 0, err
	}

	if n != len(newData) {
		return 0, fmt.Errorf("Invalid data sent %d != %d", n, len(newData))
	}

	return n - 8, nil
}

func (c *dummyConn) Close() error {
	return c.c.Close()
}

func (c *dummyConn) LocalAddr() net.Addr {
	return c.c.LocalAddr()
}

func (c *dummyConn) RemoteAddr() net.Addr {
	return c.c.RemoteAddr()
}

func (c *dummyConn) SetDeadline(t time.Time) error {
	return c.c.SetDeadline(t)
}

func (c *dummyConn) SetReadDeadline(t time.Time) error {
	return c.c.SetReadDeadline(t)
}

func (c *dummyConn) SetWriteDeadline(t time.Time) error {
	return c.c.SetWriteDeadline(t)
}
