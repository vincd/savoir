package tds

import (
	"encoding/binary"
	"fmt"

	"github.com/vincd/savoir/utils"
)

func uint16len(b []byte) uint16 {
	l := len(b)
	if len(b) > 0xFFFF {
		log.Warn("uint16len: uint16 overflow, buffer length is %d", l)
	}
	return uint16(l)
}

type TdsPacket struct {
	Type     uint8
	Status   uint8
	Length   uint16
	SPID     uint16
	PacketID uint8
	Window   uint8
	Data     []byte
}

func NewTdsPacketHeaderWithBytes(buf []byte) (*TdsPacket, error) {
	if len(buf) < 8 {
		return nil, fmt.Errorf("cannot read TDS header from buffer")
	}

	p := &TdsPacket{
		Type:     buf[0],
		Status:   buf[1],
		Length:   binary.BigEndian.Uint16(buf[2:]),
		SPID:     binary.BigEndian.Uint16(buf[4:]),
		PacketID: buf[6],
		Window:   buf[7],
		Data:     make([]byte, 0),
	}

	return p, nil
}

func NewTdsPacketWithBytes(buf []byte) (*TdsPacket, error) {
	p, err := NewTdsPacketHeaderWithBytes(buf)
	if err != nil {
		return nil, err
	}

	// TODO: handle packet status
	if p.Status != TDS_STATUS_EOM {
		return nil, fmt.Errorf("cannot handle TDS packet with status != TDS_STATUS_EOM (%d)", p.Status)
	}

	if uint16(len(buf)) < p.Length {
		return nil, fmt.Errorf("cannot read TDS data from buffer (%d < %d)", len(buf), p.Length)
	}

	p.Data = buf[8:p.Length]

	return p, nil
}

func (p *TdsPacket) Bytes() []byte {
	buf := make([]byte, 8)
	buf[0] = p.Type
	buf[1] = p.Status
	binary.BigEndian.PutUint16(buf[2:], p.Length)
	binary.BigEndian.PutUint16(buf[4:], p.SPID)
	buf[6] = p.PacketID
	buf[7] = p.Window
	buf = append(buf, p.Data...)

	return buf
}

type TdsPreloginOption struct {
	Token  uint8
	Offset uint16
	Length uint16
}

func NewTdsPreloginOptionWithBytes(data []byte) (*TdsPreloginOption, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("cannot read TDS prelogin option from buffer")
	}

	o := &TdsPreloginOption{
		Token:  data[0],
		Offset: binary.BigEndian.Uint16(data[1:]),
		Length: binary.BigEndian.Uint16(data[3:]),
	}

	return o, nil
}

func (o *TdsPreloginOption) Bytes() []byte {
	buf := make([]byte, 5)
	buf[0] = o.Token
	binary.BigEndian.PutUint16(buf[1:], o.Offset)
	binary.BigEndian.PutUint16(buf[3:], o.Length)

	return buf
}

type TdsPrelogin struct {
	VersionOption    TdsPreloginOption
	EncryptionOption TdsPreloginOption
	InstanceOption   TdsPreloginOption
	ThreadIDOption   TdsPreloginOption
	Terminator       uint8
	Version          []byte
	Encryption       []byte
	Instance         []byte
	ThreadID         []byte
}

func NewTdsPrelogin(version []byte, encryption uint8, instance string, threadID uint32) (*TdsPrelogin, error) {
	byteEncryption := []byte{encryption}
	byteInstance := []byte(instance + "\x00")
	byteThreadId := make([]byte, 4)
	binary.BigEndian.PutUint32(byteThreadId, threadID)

	prelogin := &TdsPrelogin{
		VersionOption: TdsPreloginOption{
			Token:  TDS_PRELOGIN_TOKEN_VERSION,
			Offset: 21,
			Length: uint16(len(version)),
		},
		EncryptionOption: TdsPreloginOption{
			Token:  TDS_PRELOGIN_TOKEN_ENCRYPTION,
			Offset: uint16(21 + len(version)),
			Length: 1,
		},
		InstanceOption: TdsPreloginOption{
			Token:  TDS_PRELOGIN_TOKEN_INSTANCE,
			Offset: uint16(21 + len(version) + 1),
			Length: uint16(len(byteInstance)),
		},
		ThreadIDOption: TdsPreloginOption{
			Token:  TDS_PRELOGIN_TOKEN_THREADID,
			Offset: uint16(21 + len(version) + 1 + len(byteInstance)),
			Length: uint16(len(byteThreadId)),
		},
		Terminator: TDS_PRELOGIN_TOKEN_TERMINATOR,
		Version:    version,
		Encryption: byteEncryption,
		Instance:   byteInstance,
		ThreadID:   byteThreadId,
	}

	return prelogin, nil
}

func NewTdsPreloginWithBytes(data []byte) (*TdsPrelogin, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("cannot read prelogin from buffer")
	}

	p := &TdsPrelogin{}
	i := 0
	for i < len(data) && data[i] != TDS_PRELOGIN_TOKEN_TERMINATOR {
		o, err := NewTdsPreloginOptionWithBytes(data[i:])
		if err != nil {
			return nil, err
		}
		i += 5

		if o.Token == TDS_PRELOGIN_TOKEN_VERSION {
			p.VersionOption = *o
			if len(data) < int(o.Offset+o.Length) {
				return nil, fmt.Errorf("cannot read TDS prelogin version from buffer")
			}
			p.Version = data[o.Offset : o.Offset+o.Length]
		} else if o.Token == TDS_PRELOGIN_TOKEN_ENCRYPTION {
			p.EncryptionOption = *o
			if len(data) < int(o.Offset+o.Length) {
				return nil, fmt.Errorf("cannot read TDS prelogin encryption from buffer")
			}

			if o.Length != 1 {
				return nil, fmt.Errorf("TDS prelogin encryption length is invalid (%d)", o.Length)
			}

			p.Encryption = data[o.Offset : o.Offset+o.Length]
		} else if o.Token == TDS_PRELOGIN_TOKEN_INSTANCE {
			p.InstanceOption = *o
			if len(data) < int(o.Offset+o.Length) {
				return nil, fmt.Errorf("cannot read TDS prelogin instace from buffer")
			}

			p.Instance = data[o.Offset : o.Offset+o.Length]
		} else if o.Token == TDS_PRELOGIN_TOKEN_THREADID {
			p.EncryptionOption = *o
			if len(data) < int(o.Offset+o.Length) {
				return nil, fmt.Errorf("cannot read TDS prelogin threadid from buffer")
			}

			p.ThreadID = data[o.Offset : o.Offset+o.Length]
		} else {
			return nil, fmt.Errorf("TDS prelogin has an unsupported option token %d", o.Token)
		}
	}

	if data[i] != TDS_PRELOGIN_TOKEN_TERMINATOR {
		return nil, fmt.Errorf("cannot read TDS prelogin terminator from buffer")
	}

	return p, nil
}

func (p *TdsPrelogin) Bytes() []byte {
	buf := make([]byte, 0)
	buf = append(buf, p.VersionOption.Bytes()...)
	buf = append(buf, p.EncryptionOption.Bytes()...)
	buf = append(buf, p.InstanceOption.Bytes()...)
	buf = append(buf, p.ThreadIDOption.Bytes()...)
	buf = append(buf, p.Terminator)
	buf = append(buf, p.Version...)
	buf = append(buf, p.Encryption...)
	buf = append(buf, p.Instance...)
	buf = append(buf, p.ThreadID...)

	return buf
}

type TdsLogin struct {
	Length        uint32
	TDSVersion    uint32
	PacketSize    uint32
	ClientVersion uint32
	ClientPID     uint32
	ConnectionID  uint32
	OptionFlags1  uint8
	OptionFlags2  uint8
	SQLTypeFlags  uint8
	ReservedFlags uint8
	TimeZone      uint32
	Collation     uint32

	ClientNameOffset  uint16
	ClientNameLength  uint16
	UsernameOffset    uint16
	UsernameLength    uint16
	PasswordOffset    uint16
	PasswordLength    uint16
	AppNameOffset     uint16
	AppNameLength     uint16
	ServerNameOffset  uint16
	ServerNameLength  uint16
	Unknow1Offset     uint16
	Unknow1Length     uint16
	LibraryNameOffset uint16
	LibraryNameLength uint16
	LocalOffset       uint16
	LocalLength       uint16
	DatabaseOffset    uint16
	DatabaseLength    uint16
	ClientID          [6]byte // \x01\x02\x03\x04\x05\x06
	SSPIOffset        uint16
	SSPILength        uint16
	AtchDBFileOffset  uint16
	AtchDBFileLength  uint16

	ClientName  []byte
	Username    []byte
	Password    []byte
	AppName     []byte
	ServerName  []byte
	Unknow1     []byte
	LibraryName []byte
	Local       []byte
	Database    []byte
	SSPI        []byte
	AtchDBFile  []byte
}

func NewTdsLogin() (*TdsLogin, error) {
	clientName, err := utils.UTF16Encode("Savoir")
	if err != nil {
		return nil, err
	}

	t := &TdsLogin{
		TDSVersion:    0x71,
		ClientVersion: 7,
		OptionFlags1:  0xe0,
		ClientName:    clientName,
		AppName:       clientName,
		LibraryName:   clientName,
	}

	return t, nil
}

func (t *TdsLogin) Bytes() []byte {
	offset := uint16(36 + 44 + 6)

	t.ClientNameOffset = offset
	t.ClientNameLength = uint16(len(t.ClientName) / 2)
	offset += t.ClientNameLength * 2

	if len(t.Username) > 0 {
		t.UsernameOffset = offset
	} else {
		t.UsernameOffset = 0
	}
	t.UsernameLength = uint16len(t.Username) / 2
	offset += t.UsernameLength * 2

	if len(t.Password) > 0 {
		t.PasswordOffset = offset
	} else {
		t.PasswordOffset = 0
	}
	t.PasswordLength = uint16len(t.Password) / 2
	offset += t.PasswordLength * 2

	t.AppNameOffset = offset
	t.AppNameLength = uint16len(t.AppName) / 2
	offset += t.AppNameLength * 2

	t.ServerNameOffset = offset
	t.ServerNameLength = uint16len(t.ServerName) / 2
	offset += t.ServerNameLength * 2

	t.LibraryNameOffset = offset
	t.LibraryNameLength = uint16len(t.LibraryName) / 2
	offset += t.LibraryNameLength * 2

	t.LocalOffset = offset
	t.LocalLength = uint16len(t.Local) / 2
	offset += t.LocalLength * 2

	t.DatabaseOffset = offset
	t.DatabaseLength = uint16len(t.Database) / 2
	offset += t.DatabaseLength * 2

	t.SSPIOffset = offset
	t.SSPILength = uint16len(t.SSPI)
	offset += t.SSPILength

	t.AtchDBFileOffset = offset
	t.AtchDBFileLength = uint16len(t.AtchDBFile) / 2

	buf := make([]byte, 36+44+6)
	binary.LittleEndian.PutUint32(buf[0:], t.Length)
	binary.BigEndian.PutUint32(buf[4:], t.TDSVersion)
	binary.LittleEndian.PutUint32(buf[8:], t.PacketSize)
	binary.BigEndian.PutUint32(buf[12:], t.ClientVersion)
	binary.LittleEndian.PutUint32(buf[16:], t.ClientPID)
	binary.LittleEndian.PutUint32(buf[20:], t.ConnectionID)
	buf[24] = t.OptionFlags1
	buf[25] = t.OptionFlags2
	buf[26] = t.SQLTypeFlags
	buf[27] = t.ReservedFlags
	binary.LittleEndian.PutUint32(buf[28:], t.TimeZone)
	binary.LittleEndian.PutUint32(buf[32:], t.Collation)

	binary.LittleEndian.PutUint16(buf[36:], t.ClientNameOffset)
	binary.LittleEndian.PutUint16(buf[38:], t.ClientNameLength)
	binary.LittleEndian.PutUint16(buf[40:], t.UsernameOffset)
	binary.LittleEndian.PutUint16(buf[42:], t.UsernameLength)
	binary.LittleEndian.PutUint16(buf[44:], t.PasswordOffset)
	binary.LittleEndian.PutUint16(buf[46:], t.PasswordLength)
	binary.LittleEndian.PutUint16(buf[48:], t.AppNameOffset)
	binary.LittleEndian.PutUint16(buf[50:], t.AppNameLength)
	binary.LittleEndian.PutUint16(buf[52:], t.ServerNameOffset)
	binary.LittleEndian.PutUint16(buf[54:], t.ServerNameLength)
	binary.LittleEndian.PutUint16(buf[56:], t.Unknow1Offset)
	binary.LittleEndian.PutUint16(buf[58:], t.Unknow1Length)
	binary.LittleEndian.PutUint16(buf[60:], t.LibraryNameOffset)
	binary.LittleEndian.PutUint16(buf[62:], t.LibraryNameLength)
	binary.LittleEndian.PutUint16(buf[64:], t.LocalOffset)
	binary.LittleEndian.PutUint16(buf[66:], t.LocalLength)
	binary.LittleEndian.PutUint16(buf[68:], t.DatabaseOffset)
	binary.LittleEndian.PutUint16(buf[70:], t.DatabaseLength)
	buf[72] = 0x01
	buf[73] = 0x02
	buf[74] = 0x03
	buf[75] = 0x04
	buf[76] = 0x05
	buf[77] = 0x06
	binary.LittleEndian.PutUint16(buf[78:], t.SSPIOffset)
	binary.LittleEndian.PutUint16(buf[80:], t.SSPILength)
	binary.LittleEndian.PutUint16(buf[82:], t.AtchDBFileOffset)
	binary.LittleEndian.PutUint16(buf[84:], t.AtchDBFileLength)

	buf = append(buf, t.ClientName...)
	buf = append(buf, t.Username...)
	buf = append(buf, t.Password...)
	buf = append(buf, t.AppName...)
	buf = append(buf, t.ServerName...)
	buf = append(buf, t.LibraryName...)
	buf = append(buf, t.Local...)
	buf = append(buf, t.Database...)
	buf = append(buf, t.SSPI...)
	buf = append(buf, t.AtchDBFile...)

	return buf
}
