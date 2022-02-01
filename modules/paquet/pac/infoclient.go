package pac

import (
	"encoding/binary"
	"fmt"

	"github.com/vincd/savoir/utils"
	"gopkg.in/jcmturner/rpc.v1/mstypes"
)

type ClientInfo struct {
	ClientId   mstypes.FileTime
	NameLength uint16
	Name       string
}

func NewClientInfo(data []byte) (*ClientInfo, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("cannot read ClientId")
	}
	clientId := mstypes.FileTime{
		LowDateTime:  binary.LittleEndian.Uint32(data[0:4]),
		HighDateTime: binary.LittleEndian.Uint32(data[4:8]),
	}

	if len(data) < 10 {
		return nil, fmt.Errorf("cannot read NameLength")
	}
	nameLength := binary.LittleEndian.Uint16(data[8:10])

	if len(data) < 10+int(nameLength) {
		return nil, fmt.Errorf("cannot read Name")
	}
	name, err := utils.UTF16DecodeFromBytes(data[10 : 10+nameLength])
	if err != nil {
		return nil, err
	}

	return &ClientInfo{
		ClientId:   clientId,
		NameLength: nameLength,
		Name:       name,
	}, nil
}

func (c *ClientInfo) String() string {
	return fmt.Sprintf("ClientInfo{ClientId: %s, Name: %s}", c.ClientId.Time(), c.Name)
}
