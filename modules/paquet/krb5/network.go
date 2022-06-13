package krb5

import (
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/net/proxy"
)

type KerberosMessage interface {
	Marshal() ([]byte, error)
	Unmarshal([]byte) error
}

func SendMessage(dialer proxy.Dialer, dcIp string, msg KerberosMessage) ([]byte, error) {
	req, err := msg.Marshal()
	if err != nil {
		return nil, fmt.Errorf("cannot marshal Kerberos message: %s", err)
	}

	con, err := dialer.Dial("tcp", fmt.Sprintf("%s:%d", dcIp, KERB_KDC_PORT))
	if err != nil {
		return nil, fmt.Errorf("cannot contact KDC with IP %s: %s", dcIp, err)
	}
	defer con.Close()

	size := make([]byte, 4)
	binary.BigEndian.PutUint32(size, uint32(len(req)))

	if _, err := con.Write(append(size, req...)); err != nil {
		return nil, fmt.Errorf("cannot send Kerberos message: %s", err)
	}

	krbSizeBytes := make([]byte, 4)
	if _, err := con.Read(krbSizeBytes); err != nil {
		return nil, fmt.Errorf("cannot read Kerberos response size: %s", err)
	}

	krbSize := binary.BigEndian.Uint32(krbSizeBytes)
	krbBytes := make([]byte, krbSize)
	if _, err = io.ReadFull(con, krbBytes); err != nil {
		return nil, fmt.Errorf("cannot read Kerberos data (size: %d): %s", krbSize, err)
	}

	krbType := krbBytes[0] & 0x1f
	if krbType == 0x1f {
		return nil, fmt.Errorf("kerberos response type is invalid: 0x%x", krbType)
	}

	return krbBytes, nil
}
