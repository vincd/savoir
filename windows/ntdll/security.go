package ntdll

import (
	"fmt"

	"github.com/vincd/savoir/utils"
	"github.com/vincd/savoir/utils/binary"
)

type SidIdentifierAuthority struct {
	Value [6]byte
}

type Sid struct {
	Revision            byte
	SubAuthorityCount   byte
	IdentifierAuthority SidIdentifierAuthority
	SubAuthority        []uint32
}

func (sid *Sid) Decode(r utils.MemoryReader, ptr binary.Pointer) error {
	if ptr == 0 {
		return nil
	}

	buf, err := r.Read(ptr, 8)
	if err != nil {
		return err
	}

	sid.Revision = buf[0]
	sid.SubAuthorityCount = buf[1]
	sid.IdentifierAuthority = SidIdentifierAuthority{
		Value: [6]byte{buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]},
	}
	sid.SubAuthority = make([]uint32, 0)

	ptr += 8
	for i := byte(0); i < sid.SubAuthorityCount; i++ {
		subAuthority, err := r.ReadUInt32(ptr)
		if err != nil {
			return err
		}

		sid.SubAuthority = append(sid.SubAuthority, subAuthority)
		ptr += 4
	}

	return nil
}

func (sid Sid) String() string {
	identifierAuthority := uint64(sid.IdentifierAuthority.Value[5]) | uint64(sid.IdentifierAuthority.Value[4])<<8 |
		uint64(sid.IdentifierAuthority.Value[3])<<16 | uint64(sid.IdentifierAuthority.Value[2])<<24 |
		uint64(sid.IdentifierAuthority.Value[1])<<32 | uint64(sid.IdentifierAuthority.Value[0])<<40

	s := fmt.Sprintf("S-%d-%d", sid.Revision, identifierAuthority)
	for _, a := range sid.SubAuthority {
		s += fmt.Sprintf("-%d", a)
	}

	return s
}
