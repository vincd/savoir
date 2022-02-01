package pac

import (
	"encoding/binary"
	"fmt"

	"github.com/vincd/savoir/utils"
)

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/1c0d6e11-6443-4846-b744-f9f810a504eb
type UPNDNSInfo struct {
	UPNLength           uint16
	UPNOffset           uint16
	DNSDomainNameLength uint16
	DNSDomainNameOffset uint16
	Flags               uint32
	UPN                 string
	DNSDomainName       string
}

func NewUPNDNSInfo(data []byte) (*UPNDNSInfo, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("cannot read UPNDNSInfo")
	}

	upnDnsInfo := &UPNDNSInfo{
		UPNLength:           binary.LittleEndian.Uint16(data[0:2]),
		UPNOffset:           binary.LittleEndian.Uint16(data[2:4]),
		DNSDomainNameLength: binary.LittleEndian.Uint16(data[4:6]),
		DNSDomainNameOffset: binary.LittleEndian.Uint16(data[6:8]),
		Flags:               binary.LittleEndian.Uint32(data[8:12]),
	}

	if len(data) < int(upnDnsInfo.UPNLength)+int(upnDnsInfo.UPNOffset) {
		return nil, fmt.Errorf("cannot read UPN")
	}

	upn, err := utils.UTF16DecodeFromBytes(data[upnDnsInfo.UPNOffset : upnDnsInfo.UPNOffset+upnDnsInfo.UPNLength])
	if err != nil {
		return nil, err
	}
	upnDnsInfo.UPN = upn

	if len(data) < int(upnDnsInfo.DNSDomainNameLength)+int(upnDnsInfo.DNSDomainNameOffset) {
		return nil, fmt.Errorf("cannot read DNSDomainName")
	}

	dnsDomainName, err := utils.UTF16DecodeFromBytes(data[upnDnsInfo.DNSDomainNameOffset : upnDnsInfo.DNSDomainNameOffset+upnDnsInfo.DNSDomainNameLength])
	if err != nil {
		return nil, err
	}
	upnDnsInfo.DNSDomainName = dnsDomainName

	return upnDnsInfo, nil
}

func (i *UPNDNSInfo) String() string {
	return fmt.Sprintf("UPNDNSInfo{UPN: %s, DNSDomainName: %s, Flags: 0x%x}", i.UPN, i.DNSDomainName, i.Flags)
}
