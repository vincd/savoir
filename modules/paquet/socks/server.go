package socks

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
)

// https://datatracker.ietf.org/doc/html/rfc1928#section-4
type SocksRequest struct {
	ver    uint8
	cmd    uint8
	rsv    uint8
	atyp   uint8
	ip     net.IP
	domain string
	port   uint16
}

// function to check the buffer is not empty and version is correct
func checkVersion5(buf []byte) error {
	if len(buf) == 0 {
		return fmt.Errorf("socks buffer is empty")
	}

	if buf[0] != Version5 {
		return fmt.Errorf("socks server hanlde SOCKS5 only")
	}

	return nil
}

func proxyConn(dst io.Writer, src io.Reader, errCh chan error) {
	_, err := io.Copy(dst, src)
	errCh <- err
}

type Server struct {
	username string
	password string
}

func NewServer() (*Server, error) {
	s := &Server{
		username: "",
		password: "",
	}

	return s, nil
}

func (s *Server) Serve(network string, serverUri string) error {
	u, err := url.Parse(serverUri)
	if err != nil {
		return err
	}

	if u.Scheme != "socks5" {
		return fmt.Errorf("URL scheme %s is invalid, this server support only socks5", u.Scheme)
	}

	username := u.User.Username()
	password, _ := u.User.Password()

	if len(username) > 255 || len(password) > 255 {
		return fmt.Errorf("username/password length are too long")
	}

	s.username = username
	s.password = password

	if len(s.username) > 0 && len(s.password) > 0 {
		fmt.Printf("Start socks server on %s with authentication\n", u.Host)
	} else {
		fmt.Printf("Start socks server on %s\n", u.Host)
	}

	l, err := net.Listen(network, u.Host)
	if err != nil {
		return fmt.Errorf("cannot listen socks server: %s", err)
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}

		go func(conn net.Conn) {
			if err := s.handleConn(conn); err != nil {
				fmt.Printf("Error: %s\n", err)
			}
		}(conn)
	}
}

// handle a new connection on the server
func (s *Server) handleConn(conn net.Conn) error {
	defer conn.Close()

	if err := s.handleAuthentication(conn); err != nil {
		return err
	}

	request, err := s.handleRequest(conn)
	if err != nil {
		return err
	}

	switch request.cmd {
	case CmdConnect:
		return s.handleCmdConnect(conn, request)
	default:
		if _, err := conn.Write([]byte{Version5, StatusCommandNotSupportedProtocolError}); err != nil {
			return fmt.Errorf("cannot send StatusCommandNotSupportedProtocolError: %s", err)
		}

		return fmt.Errorf("unsupported command with code %d", request.cmd)
	}
}

func (s *Server) handleAuthentication(conn net.Conn) error {
	// version + nAuth + 0xff methods
	buf := make([]byte, 0xff+2)
	if _, err := conn.Read(buf); err != nil {
		return err
	}

	if err := checkVersion5(buf); err != nil {
		return err
	}

	// TODO: handle SOCKS5 authentication methods
	nAuth := buf[1]
	if nAuth > 0 {
		methods := buf[2 : 2+nAuth]
		for _, method := range methods {
			if method == AuthMethodNotRequired && len(s.username) == 0 && len(s.password) == 0 {
				// Choose No authentication method
				if _, err := conn.Write([]byte{Version5, AuthMethodNotRequired}); err != nil {
					return fmt.Errorf("cannot send AuthMethodNotRequired: %s", err)
				}
				return nil
			} else if method == UsernamePassword && len(s.username) > 0 && len(s.password) > 0 {
				// Choose user/password authentication method
				if _, err := conn.Write([]byte{Version5, UsernamePassword}); err != nil {
					return fmt.Errorf("cannot send UsernamePassword: %s", err)
				}

				// auth version + username length + 0xFF + password length + 0xFF
				buf := make([]byte, 1+1+0xff+1+0xff)
				if _, err := conn.Read(buf); err != nil {
					return fmt.Errorf("cannot read username and password: %s", err)
				}

				if buf[0] != AuthUsernamePasswordVersion {
					return fmt.Errorf("client sends invalid authentication version: %d", buf[0])
				}

				usernameLength := buf[1]
				username := string(buf[2 : 2+usernameLength])
				passwordLength := buf[2+usernameLength]
				password := string(buf[3+usernameLength : 3+usernameLength+passwordLength])

				// not time constant...
				if s.username != username || s.password != password {
					if _, err := conn.Write([]byte{AuthUsernamePasswordVersion, AuthStatusFailure}); err != nil {
						return fmt.Errorf("cannot send AuthStatusFailure: %s", err)
					}
					return fmt.Errorf("invalid username/password provided")
				}

				if _, err := conn.Write([]byte{AuthUsernamePasswordVersion, AuthStatusSucceeded}); err != nil {
					return fmt.Errorf("cannot send AuthStatusSucceeded: %s", err)
				}

				return nil
			}
		}
	}

	// we're here because the client sends a method we do not support (yet!)
	if _, err := conn.Write([]byte{Version5, NoAcceptableMethods}); err != nil {
		return fmt.Errorf("cannot send NoAcceptableMethods: %s", err)
	}

	return nil
}

func (s *Server) handleRequest(conn net.Conn) (SocksRequest, error) {
	// version + cmd + rsv + atyp + domainLength + 0xFF + port(2 bytes)
	buf := make([]byte, 0xff+7)
	if _, err := conn.Read(buf); err != nil {
		return SocksRequest{}, err
	}

	if err := checkVersion5(buf); err != nil {
		return SocksRequest{}, err
	}

	request := SocksRequest{
		ver:  buf[0],
		cmd:  buf[1],
		rsv:  buf[2],
		atyp: buf[3],
	}

	switch request.atyp {
	case AddrTypeIPv4:
		request.ip = (net.IP)(buf[4 : 4+4])
		request.port = binary.BigEndian.Uint16(buf[4+4 : 4+4+2])
	case AddrTypeFQDN:
		domainLength := buf[4]
		request.domain = string(buf[4+1 : 4+1+domainLength])
		request.port = binary.BigEndian.Uint16(buf[4+1+domainLength : 4+1+domainLength+2])
	case AddrTypeIPv6:
		request.ip = (net.IP)(buf[4 : 4+16])
		request.port = binary.BigEndian.Uint16(buf[4+16 : 4+16+2])
	default:
		if _, err := conn.Write([]byte{Version5, StatusCommandNotSupportedProtocolError}); err != nil {
			return SocksRequest{}, fmt.Errorf("cannot send StatusCommandNotSupportedProtocolError: %s", err)
		}
		return SocksRequest{}, fmt.Errorf("unsuported atyp received: %d", request.atyp)
	}

	return request, nil
}

func (s *Server) handleCmdConnect(conn net.Conn, request SocksRequest) error {
	var address string

	// If there is a domain then use the internal DNS resolver using Dial
	if len(request.domain) > 0 {
		address = net.JoinHostPort(request.domain, strconv.FormatInt(int64(request.port), 10))
	} else {
		address = net.JoinHostPort(request.ip.String(), strconv.FormatInt(int64(request.port), 10))
	}

	fmt.Printf("Connect to %s\n", address)
	target, err := net.Dial("tcp", address)
	if err != nil {
		if _, err := conn.Write([]byte{Version5, StatusNetworkUnreachable}); err != nil {
			return fmt.Errorf("cannot send StatusNetworkUnreachable: %s", err)
		}
		return fmt.Errorf("cannot dial target %s: %s", net.JoinHostPort(request.ip.String(), strconv.FormatInt(int64(request.port), 10)), err)
	}
	defer target.Close()

	// Get local and remote TPC addresses
	local := target.LocalAddr().(*net.TCPAddr)
	remote := conn.RemoteAddr().(*net.TCPAddr)

	// https://datatracker.ietf.org/doc/html/rfc1928#section-6
	response := []byte{
		Version5,
		StatusSucceeded,
		0x00,
		AddrTypeIPv4,
		local.IP[0], local.IP[1], local.IP[2], local.IP[3],
		byte((local.Port >> 8) & 0xFF),
		byte((local.Port >> 0) & 0xFF),
	}
	_, err = conn.Write(response)
	if err != nil {
		return fmt.Errorf("cannot send socks response: %s", err)
	}

	fmt.Printf("Start proxy: %s<->%s\n", remote, address)
	errorChannels := make(chan error, 2)
	go proxyConn(target, bufio.NewReader(conn), errorChannels)
	go proxyConn(conn, target, errorChannels)

	for i := 0; i < 2; i++ {
		err := <-errorChannels
		if err != nil {
			return fmt.Errorf("receive an error while proxing: %s", err)
		}
	}
	fmt.Printf("End proxy: %s<->%s\n", remote, address)

	return nil
}
