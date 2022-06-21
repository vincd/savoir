package utils

import (
	"golang.org/x/net/proxy"

	"github.com/vincd/savoir/modules/paquet/socks"
)

// Get dialer to server (using socks)
func GetDialerWithSocks(socksAddress string) (proxy.Dialer, error) {
	if len(socksAddress) > 0 {
		dialer, err := socks.NewDialer(socksAddress)
		if err != nil {
			return nil, err
		}

		return dialer, nil
	} else {
		return proxy.Direct, nil
	}
}
