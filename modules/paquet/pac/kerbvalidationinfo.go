package pac

import (
	"bytes"
	"fmt"

	// TODO: implement my own NDR decoder
	// TODO: use structures impemented in windows package
	"gopkg.in/jcmturner/rpc.v1/mstypes"
	"gopkg.in/jcmturner/rpc.v1/ndr"
)

// From: https://github.com/jcmturner/gokrb5/blob/master/pac/kerb_validation_info.go
type KerbValidationInfo struct {
	LogOnTime              mstypes.FileTime
	LogOffTime             mstypes.FileTime
	KickOffTime            mstypes.FileTime
	PasswordLastSet        mstypes.FileTime
	PasswordCanChange      mstypes.FileTime
	PasswordMustChange     mstypes.FileTime
	EffectiveName          mstypes.RPCUnicodeString
	FullName               mstypes.RPCUnicodeString
	LogonScript            mstypes.RPCUnicodeString
	ProfilePath            mstypes.RPCUnicodeString
	HomeDirectory          mstypes.RPCUnicodeString
	HomeDirectoryDrive     mstypes.RPCUnicodeString
	LogonCount             uint16
	BadPasswordCount       uint16
	UserID                 uint32
	PrimaryGroupID         uint32
	GroupCount             uint32
	GroupIDs               []mstypes.GroupMembership `ndr:"pointer,conformant"`
	UserFlags              uint32
	UserSessionKey         mstypes.UserSessionKey
	LogonServer            mstypes.RPCUnicodeString
	LogonDomainName        mstypes.RPCUnicodeString
	LogonDomainID          mstypes.RPCSID `ndr:"pointer"`
	Reserved1              [2]uint32      // Has 2 elements
	UserAccountControl     uint32
	SubAuthStatus          uint32
	LastSuccessfulILogon   mstypes.FileTime
	LastFailedILogon       mstypes.FileTime
	FailedILogonCount      uint32
	Reserved3              uint32
	SIDCount               uint32
	ExtraSIDs              []mstypes.KerbSidAndAttributes `ndr:"pointer,conformant"`
	ResourceGroupDomainSID mstypes.RPCSID                 `ndr:"pointer"`
	ResourceGroupCount     uint32
	ResourceGroupIDs       []mstypes.GroupMembership `ndr:"pointer,conformant"`
}

func NewKerbValidationInfo(data []byte) (*KerbValidationInfo, error) {
	// This structure is NDR encoded, so we use an external library to parse it
	dec := ndr.NewDecoder(bytes.NewReader(data))
	kerbValidationInfo := &KerbValidationInfo{}
	if err := dec.Decode(kerbValidationInfo); err != nil {
		return nil, fmt.Errorf("cannot read KerbValidationInfo: %s", err)
	}

	return kerbValidationInfo, nil
}

func (v *KerbValidationInfo) String() string {
	return fmt.Sprintf("KerbValidationInfo{EffectiveName: %s, LogonServer: %s, LogonDomainName: %s, ...}", v.EffectiveName.Value, v.LogonServer.Value, v.LogonDomainName.Value)
}
