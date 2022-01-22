package sam

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"fmt"
	"strconv"

	"github.com/vincd/savoir/utils"
	"github.com/vincd/savoir/windows/registry"
)

type SamHive struct {
	registry.Hive
}

type SamCredentials struct {
	Username        string `json:"username"`
	Rid             uint32 `json:"rid"`
	LmHash          string `json:"lm_hash"`
	NtlmHash        string `json:"ntlm_hash"`
	LmHistoryHash   string `json:"lm_hash_history"`
	NtlmHistoryHash string `json:"ntlm_hash_history"`
}

func (c SamCredentials) String() string {
	return fmt.Sprintf("%s:%d:%s:%s (%s:%s)", c.Username, c.Rid, c.LmHash, c.NtlmHash, c.LmHistoryHash, c.NtlmHistoryHash)
}

type RegistrySamDomainAccount struct {
	Revision                     uint16
	_                            uint16
	_                            uint32
	CreationTime                 uint64
	DomainModifiedCount          uint64
	MaxPasswordAge               uint64
	MinPasswordAge               uint64
	ForceLogoff                  uint64
	LockoutDuration              uint64
	LockoutObservationWindow     uint64
	ModifiedCountAtLastPromotion uint64
	NextRid                      uint32
	PasswordProperties           uint32
	MinPasswordLength            uint16
	PasswordHistoryLength        uint16
	LockoutThreshold             uint16
	_                            uint16
	ServerState                  uint32
	ServerRole                   uint32
	UasCompatibilityRequired     uint32
	_                            uint32
	Keys1                        [64]byte
	Keys2                        [64]byte
	_                            uint32
	_                            uint32
}

type RegistrySamKeyData struct {
	Revision uint32
	Length   uint32
	Salt     [16]byte
	Key      [16]byte
	CheckSum [16]byte
	_        uint32
	_        uint32
}

type RegistrySamKeyDataAES struct {
	Revision uint32
	Length   uint32
	CheckLen uint32
	ChtaLen  uint32
	Salt     [16]byte
	Data     [16]byte
}

type RegistrySamEntry struct {
	Offset uint32
	Lenght uint32
	Unk    uint32
}

type RegistrySamUserAccountWithoutData struct {
	Unk0_header    RegistrySamEntry
	Username       RegistrySamEntry
	Fullname       RegistrySamEntry
	Comment        RegistrySamEntry
	UserComment    RegistrySamEntry
	_              RegistrySamEntry
	Homedir        RegistrySamEntry
	HomedirConnect RegistrySamEntry
	ScriptPath     RegistrySamEntry
	ProfilePath    RegistrySamEntry
	Workstations   RegistrySamEntry
	HoursAllowed   RegistrySamEntry
	_              RegistrySamEntry
	LMHash         RegistrySamEntry
	NTLMHash       RegistrySamEntry
	NTLMHistory    RegistrySamEntry
	LMHistory      RegistrySamEntry
}

type RegistrySamUserAccount struct {
	RegistrySamUserAccountWithoutData
	Data []byte
}

type RegistrySamHashAESWithoutData struct {
	PEKID      uint16
	Revision   uint16
	DataOffset uint32
	Salt       [16]byte
}

type RegistrySamHashAES struct {
	RegistrySamHashAESWithoutData
	Data []byte
}

var QWERTY_CONST = []byte("!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\x00")
var DIGITS_CONST = []byte("0123456789012345678901234567890123456789\x00")

// returns rc4.decrypt(md5(key), data)
func arc4Decrypt(key []byte, cipherData []byte) ([]byte, error) {
	rc4Key := md5.Sum(key)
	rc4Cipher, err := rc4.NewCipher(rc4Key[:])
	if err != nil {
		return nil, err
	}

	plainData := make([]byte, len(cipherData))
	rc4Cipher.XORKeyStream(plainData, cipherData)

	return plainData, nil
}

func ridToKey(rid uint32) (k1, k2 []byte) {
	key := make([]byte, 4)
	binary.LittleEndian.PutUint32(key, rid)
	key1 := []byte{key[0], key[1], key[2], key[3], key[0], key[1], key[2]}
	key2 := []byte{key[3], key[0], key[1], key[2], key[3], key[0], key[1]}

	return transformRidKey(key1), transformRidKey(key2)
}

func transformRidKey(key []byte) []byte {
	transformedKey := []byte{}
	transformedKey = append(transformedKey, key[0]>>0x01)
	transformedKey = append(transformedKey, ((key[0]&0x01)<<6)|key[1]>>2)
	transformedKey = append(transformedKey, ((key[1]&0x03)<<5)|key[2]>>3)
	transformedKey = append(transformedKey, ((key[2]&0x07)<<4)|key[3]>>4)
	transformedKey = append(transformedKey, ((key[3]&0x0f)<<3)|key[4]>>5)
	transformedKey = append(transformedKey, ((key[4]&0x1f)<<2)|key[5]>>6)
	transformedKey = append(transformedKey, ((key[5]&0x3f)<<1)|key[6]>>7)
	transformedKey = append(transformedKey, key[6]&0x7f)

	for i := 0; i < 8; i++ {
		transformedKey[i] = (transformedKey[i] << 1) & 0xfe
	}

	return transformedKey
}

func decryptHash(encryptedHash []byte, rid uint32) ([]byte, error) {
	k1, k2 := ridToKey(rid)
	c1, err := des.NewCipher(k1)
	if err != nil {
		return nil, err
	}
	c2, err := des.NewCipher(k2)
	if err != nil {
		return nil, err
	}
	p1 := make([]byte, 8)
	p2 := make([]byte, 8)

	c1.Decrypt(p1, encryptedHash[:8])
	c2.Decrypt(p2, encryptedHash[8:])

	return append(p1, p2...), nil
}

// Get SAM key (hbootkey)
func (h *SamHive) GetSamKey(sysKey []byte) ([]byte, error) {
	node, err := h.OpenKey("SAM\\Domains\\Account")
	if err != nil {
		return nil, err
	}

	data, err := node.QueryValue("F")
	if err != nil {
		return nil, err
	}

	buf := bytes.NewBuffer(data)
	domainAccount := &RegistrySamDomainAccount{}
	err = binary.Read(buf, binary.LittleEndian, domainAccount)
	if err != nil {
		return nil, err
	}

	switch domainAccount.Revision {
	case 2, 3:
		switch domainAccount.Keys1[0] {
		case 1:
			rc4Key := &RegistrySamKeyData{}
			err = binary.Read(bytes.NewBuffer(domainAccount.Keys1[0:64]), binary.LittleEndian, rc4Key)
			if err != nil {
				return nil, err
			}

			hashData := append(rc4Key.Salt[:], QWERTY_CONST...)
			hashData = append(hashData, sysKey...)
			hashData = append(hashData, DIGITS_CONST...)

			plainHash, err := arc4Decrypt(hashData, append(rc4Key.Key[:], rc4Key.CheckSum[:]...))
			if err != nil {
				return nil, err
			}

			hashData = append(plainHash[:16], DIGITS_CONST...)
			hashData = append(hashData, plainHash[:16]...)
			hashData = append(hashData, QWERTY_CONST...)
			checksum := md5.Sum(hashData)

			if bytes.Compare(checksum[:], plainHash[16:]) != 0 {
				// https://github.com/SecureAuthCorp/impacket/blob/cd4fe47cfcb72d7d35237a99e3df95cedf96e94f/impacket/examples/secretsdump.py#L1183
				return nil, fmt.Errorf("Sam key CheckSum failed, Syskey startup password probably in use! :(")
			}

			return plainHash[:16], nil
		case 2:
			aesKey := &RegistrySamKeyDataAES{}
			err = binary.Read(bytes.NewBuffer(domainAccount.Keys1[0:64]), binary.LittleEndian, aesKey)
			if err != nil {
				return nil, err
			}

			block, err := aes.NewCipher(sysKey)
			if err != nil {
				return nil, err
			}

			aesCBC := cipher.NewCBCDecrypter(block, aesKey.Salt[0:aes.BlockSize])
			ciphertext := aesKey.Data[:aes.BlockSize]
			aesCBC.CryptBlocks(ciphertext, ciphertext)

			return ciphertext, nil
		default:
			return nil, fmt.Errorf("Unknow Struct Key revision %u", domainAccount.Keys1[0])
		}
	default:
		return nil, fmt.Errorf("Unknow F revision %u", domainAccount.Revision)
	}

	return nil, nil
}

func (h *SamHive) GetHash(samKey []byte, userAccountData []byte, rid uint32, entry RegistrySamEntry, constant []byte) ([]byte, error) {
	hashEntry := userAccountData[entry.Offset+0xCC : entry.Offset+0xCC+entry.Lenght]

	switch hashEntry[2] {
	case 1:
		if entry.Lenght < 20 { // 4 + 16
			return make([]byte, 0), nil
		}

		ridBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(ridBytes, rid)

		hashData := append(samKey[0:0x10], ridBytes...)
		hashData = append(hashData, constant...)

		cipherHash, err := arc4Decrypt(hashData, hashEntry[4:20][:])
		if err != nil {
			return nil, err
		}

		plainHash, err := decryptHash(cipherHash, rid)
		if err != nil {
			return nil, err
		}

		return plainHash, nil
	case 2:
		hashAESWithoutData := &RegistrySamHashAESWithoutData{}
		err := binary.Read(bytes.NewBuffer(hashEntry[:24]), binary.LittleEndian, hashAESWithoutData)
		if err != nil {
			return nil, err
		}

		// there is not hash to decrypt
		if hashAESWithoutData.DataOffset < 16 {
			return []byte{}, nil
		}

		dataAES := make([]byte, 0)
		if hashAESWithoutData.DataOffset > 0 {
			dataAES = append(dataAES, hashEntry[8+hashAESWithoutData.DataOffset:]...)
		}

		hashAES := &RegistrySamHashAES{
			RegistrySamHashAESWithoutData: *hashAESWithoutData,
			Data:                          dataAES,
		}

		block, err := aes.NewCipher(samKey)
		if err != nil {
			return nil, err
		}

		aesCBC := cipher.NewCBCDecrypter(block, hashAES.Salt[:])
		cipherHash := hashAES.Data[:aes.BlockSize]
		aesCBC.CryptBlocks(cipherHash, cipherHash)

		plainHash, err := decryptHash(cipherHash, rid)
		if err != nil {
			return nil, err
		}

		return plainHash, nil
	default:
		return nil, fmt.Errorf("Unknow SAM_HASH revision %d", hashEntry[2])
	}

	return nil, nil
}

var LMPASSWORD = []byte("LMPASSWORD\x00")
var LMPASSWORDHISTORY = []byte("LMPASSWORDHISTORY\x00")
var NTPASSWORD = []byte("NTPASSWORD\x00")
var NTPASSWORDHISTORY = []byte("NTPASSWORDHISTORY\x00")

func (h *SamHive) GetHashes(sysKey []byte) ([]SamCredentials, error) {
	samKey, err := h.GetSamKey(sysKey)
	if err != nil {
		return nil, err
	}

	regUsersKey, err := h.OpenKey("SAM\\Domains\\Account\\Users")
	if err != nil {
		return nil, err
	}

	usersNK, err := regUsersKey.EnumKey()
	if err != nil {
		return nil, err
	}

	credentials := make([]SamCredentials, 0)
	for _, k := range usersNK {
		if k.Name() == "Names" {
			continue
		}

		userAccountData, err := k.QueryValue("V")
		if err != nil {
			return nil, err
		}

		userAccount := &RegistrySamUserAccountWithoutData{}
		err = binary.Read(bytes.NewBuffer(userAccountData[0:0xCC]), binary.LittleEndian, userAccount)
		if err != nil {
			return nil, err
		}

		rid64, err := strconv.ParseUint(k.Name(), 16, 32)
		if err != nil {
			return nil, err
		}
		rid := uint32(rid64)

		username, err := utils.UTF16DecodeFromBytes(userAccountData[userAccount.Username.Offset+0xCC : userAccount.Username.Offset+0xCC+userAccount.Username.Lenght])
		if err != nil {
			return nil, err
		}

		lmHash, err := h.GetHash(samKey, userAccountData, rid, userAccount.LMHash, LMPASSWORD)
		if err != nil {
			return nil, err
		}

		ntlmHash, err := h.GetHash(samKey, userAccountData, rid, userAccount.NTLMHash, NTPASSWORD)
		if err != nil {
			return nil, err
		}

		lmHistoryHash, err := h.GetHash(samKey, userAccountData, rid, userAccount.LMHistory, LMPASSWORDHISTORY)
		if err != nil {
			return nil, err
		}

		ntlmHistoryHash, err := h.GetHash(samKey, userAccountData, rid, userAccount.NTLMHistory, NTPASSWORDHISTORY)
		if err != nil {
			return nil, err
		}

		credentials = append(credentials, SamCredentials{
			Username:        username,
			Rid:             rid,
			LmHash:          fmt.Sprintf("%x", lmHash),
			NtlmHash:        fmt.Sprintf("%x", ntlmHash),
			LmHistoryHash:   fmt.Sprintf("%x", lmHistoryHash),
			NtlmHistoryHash: fmt.Sprintf("%x", ntlmHistoryHash),
		})
	}

	return credentials, nil
}
