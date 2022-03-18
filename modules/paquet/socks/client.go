package socks

import (
	"golang.org/x/net/proxy"
)

func NewDialer(address string) (proxy.Dialer, error) {
	dialer, err := proxy.SOCKS5("tcp", address, nil, proxy.Direct)
	if err != nil {
		return nil, err
	}

	return dialer, nil
}
