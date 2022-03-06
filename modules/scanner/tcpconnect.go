package scanner

import (
	"fmt"
	"net"
	"strings"
	"time"
)

type TcpConnectScanner struct {
	timeout time.Duration
}

func NewTcpConnectScanner(timeout time.Duration) (*TcpConnectScanner, error) {
	return &TcpConnectScanner{timeout: timeout}, nil
}

func (s TcpConnectScanner) ScanPort(ip net.IP, port uint16) (PortStatus, error) {
	address := ""
	if ip.To4() != nil {
		address = fmt.Sprintf("%s:%d", ip, port)
	} else {
		address = fmt.Sprintf("[%s]:%d", ip, port)
	}
	d := net.Dialer{Timeout: s.timeout}
	conn, err := d.Dial("tcp", address)
	if err != nil {
		// Ugly
		if strings.Contains(err.Error(), "connection refused") {
			return PortStatus{Protocol: ProtocolTcp, IP: ip.String(), Port: port, State: PortClosed}, nil
		} else if strings.Contains(err.Error(), "too many open files") {
			fmt.Printf("Error is too many open files => reduce speed: %s\n", err)
		} else if opErr, ok := err.(*net.OpError); ok {
			if opErr.Timeout() {
				return PortStatus{Protocol: ProtocolTcp, IP: ip.String(), Port: port, State: PortTimeout}, nil
			}
		}

		fmt.Printf("Handle error: %+v\n", err)

		return PortStatus{Protocol: ProtocolTcp, IP: ip.String(), Port: port, State: PortClosed}, nil
	}

	conn.Close()

	return PortStatus{Protocol: ProtocolTcp, IP: ip.String(), Port: port, State: PortOpen}, nil
}
