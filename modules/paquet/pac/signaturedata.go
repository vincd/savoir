package pac

import (
	"encoding/binary"
	"fmt"
)

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/6e95edd3-af93-41d4-8303-6c7955297315
type PacSignatureData struct {
	SignatureType  uint32
	Signature      []byte
	RODCIdentifier uint16
}

func NewPacSignatureData(data []byte) (*PacSignatureData, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("cannot read SignatureType")
	}

	signatureType := binary.LittleEndian.Uint32(data[0:4])
	signatureLength := 0

	if signatureType == 0xFFFFFF76 {
		signatureLength = 16
	} else if signatureType == 0x0000000F || signatureType == 0x00000010 {
		signatureLength = 12
	} else {
		return nil, fmt.Errorf("SignatureType is not valid, found %d", signatureType)
	}

	if len(data) < 4+signatureLength {
		return nil, fmt.Errorf("cannot read signature")
	}

	signature := data[4 : 4+signatureLength]
	rodcIdentifier := uint16(0)
	if len(data) == 4+signatureLength+2 {
		rodcIdentifier = binary.LittleEndian.Uint16(data[4+signatureLength:])
	}

	signatureData := &PacSignatureData{
		SignatureType:  signatureType,
		Signature:      signature,
		RODCIdentifier: rodcIdentifier,
	}

	return signatureData, nil
}
