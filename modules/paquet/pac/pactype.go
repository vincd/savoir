package pac

import (
	"encoding/binary"
	"fmt"
)

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/6655b92f-ab06-490b-845d-037e6987275f
type PacType struct {
	CBuffers        uint32
	Version         uint32
	Buffers         []PacInfoBuffer
	ValidationInfo  *KerbValidationInfo
	ClientInfo      *ClientInfo
	UpnDnsInfo      *UPNDNSInfo
	ServerSignature *PacSignatureData
	KdcSignature    *PacSignatureData
	TicketSignature *PacSignatureData
}

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/3341cfa2-6ef5-42e0-b7bc-4544884bf399
type PacInfoBuffer struct {
	ULType       uint32
	CBBufferSize uint32
	Offset       uint64
}

const (
	InfoTypeKerbValidationInfo        uint32 = 1
	InfoTypePacCredentials            uint32 = 2
	InfoTypePacSignatureDataServer    uint32 = 6
	InfoTypePacSignatureDataKdc       uint32 = 7
	InfoTypePacClientInfo             uint32 = 10
	InfoTypeConstrainedDelegationInfo uint32 = 11
	InfoTypeUpnDnsInfo                uint32 = 12
	InfoTypePacClientClaimsInfo       uint32 = 13
	InfoTypePacDeviceInfo             uint32 = 14
	InfoTypePacDeviceClaimsInfo       uint32 = 15
	InfoTypePacSignatureDataTicket    uint32 = 16
)

func NewPacType(data []byte) (*PacType, error) {
	cBuffers := binary.LittleEndian.Uint32(data[0:4])
	version := binary.LittleEndian.Uint32(data[4:8])

	pacInfo := &PacType{
		CBuffers: cBuffers,
		Version:  version,
		Buffers:  make([]PacInfoBuffer, 0),
	}

	for i := uint32(0); i < cBuffers; i++ {
		ulType := binary.LittleEndian.Uint32(data[8+16*i : 8+4+16*i])
		cbBufferSize := binary.LittleEndian.Uint32(data[8+4+16*i : 8+8+16*i])
		offset := binary.LittleEndian.Uint64(data[8+8+16*i : 8+16+16*i])

		pacInfoBuffer := PacInfoBuffer{
			ULType:       ulType,
			CBBufferSize: cbBufferSize,
			Offset:       offset,
		}

		pacInfo.Buffers = append(pacInfo.Buffers, pacInfoBuffer)

		buffer := data[offset : offset+uint64(cbBufferSize)]

		switch ulType {
		case InfoTypeKerbValidationInfo:
			// Logon information (section 2.5). PAC structures MUST contain one
			// buffer of this type. Additional logon information buffers MUST be
			// ignored.
			if pacInfo.ValidationInfo != nil {
				continue
			}
			validationInfo, err := NewKerbValidationInfo(buffer)
			if err != nil {
				return nil, err
			}

			pacInfo.ValidationInfo = validationInfo

		case InfoTypePacSignatureDataServer:
			// Server checksum (section 2.8). PAC structures MUST contain one
			// buffer of this type. Additional logon server checksum buffers
			// MUST be ignored.
			if pacInfo.ServerSignature != nil {
				continue
			}
			signature, err := NewPacSignatureData(buffer)
			if err != nil {
				return nil, err
			}
			pacInfo.ServerSignature = signature

		case InfoTypePacSignatureDataKdc:
			// KDC (privilege server) checksum (section 2.8). PAC structures
			// MUST contain one buffer of this type. Additional KDC checksum
			// buffers MUST be ignored.
			if pacInfo.KdcSignature != nil {
				continue
			}
			signature, err := NewPacSignatureData(buffer)
			if err != nil {
				return nil, err
			}
			pacInfo.KdcSignature = signature

		case InfoTypePacClientInfo:
			// Client name and ticket information (section 2.7). PAC structures
			// MUST contain one buffer of this type. Additional client and
			// ticket information buffers MUST be ignored.
			if pacInfo.ClientInfo != nil {
				continue
			}
			clientInfo, err := NewClientInfo(buffer)
			if err != nil {
				return nil, err
			}

			pacInfo.ClientInfo = clientInfo

		case InfoTypeUpnDnsInfo:
			// User principal name (UPN) and Domain Name System (DNS) information
			// (section 2.10). PAC structures SHOULD NOT contain more than one
			// buffer of this type. Second or subsequent UPN and DNS information
			// buffers MUST be ignored on receipt.
			if pacInfo.UpnDnsInfo != nil {
				continue
			}
			info, err := NewUPNDNSInfo(buffer)
			if err != nil {
				return nil, err
			}
			pacInfo.UpnDnsInfo = info

		case InfoTypePacSignatureDataTicket:
			// Ticket checksum (section 2.8). PAC structures SHOULD NOT contain
			// more than one buffer of this type. Additional ticket checksum
			// buffers MUST be ignored.
			// See: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-17049
			if pacInfo.TicketSignature != nil {
				continue
			}
			signature, err := NewPacSignatureData(buffer)
			if err != nil {
				return nil, err
			}
			pacInfo.TicketSignature = signature

		default:
			return nil, fmt.Errorf("PAC InfoType is not handle: %d", ulType)
		}
	}

	return pacInfo, nil
}
