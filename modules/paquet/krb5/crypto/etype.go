package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"fmt"
	"hash"

	"github.com/vincd/savoir/modules/paquet/krb5/crypto/rfc3961"
	"github.com/vincd/savoir/modules/paquet/krb5/crypto/rfc3962"
	"github.com/vincd/savoir/modules/paquet/krb5/crypto/rfc4757"
	crypto_aes "github.com/vincd/savoir/utils/crypto"
)

// https://datatracker.ietf.org/doc/html/RFC3961#section-8
const (
	DES_CBC_CRC int32 = 1
	DES_CBC_MD4 int32 = 2
	DES_CBC_MD5 int32 = 3
	// DES_CBC_RAW                  int32 = 4
	DES3_CBC_MD5 int32 = 5
	// DES3_CBC_RAW                 int32 = 6
	DES3_CBC_SHA1 int32 = 7
	// DES_HMAC_SHA1                int32 = 8
	DSAWITHSHA1_CMSOID           int32 = 9
	MD5WITHRSAENCRYPTION_CMSOID  int32 = 10
	SHA1WITHRSAENCRYPTION_CMSOID int32 = 11
	RC2CBC_ENVOID                int32 = 12
	RSAENCRYPTION_ENVOID         int32 = 13
	RSAES_OAEP_ENV_OID           int32 = 14
	DES_EDE3_CBC_ENV_OID         int32 = 15
	DES3_CBC_SHA1_KD             int32 = 16
	AES128_CTS_HMAC_SHA1_96      int32 = 17
	AES256_CTS_HMAC_SHA1_96      int32 = 18
	// AES128_CTS_HMAC_SHA256_128   int32 = 19
	// AES256_CTS_HMAC_SHA384_192   int32 = 20
	RC4_HMAC     int32 = 23
	RC4_HMAC_EXP int32 = 24
	// CAMELLIA128_CTS_CMAC         int32 = 25
	// CAMELLIA256_CTS_CMAC         int32 = 26
	SUBKEY_KEYMATERIAL int32 = 65
)

func ETypeToString(eType int32) string {
	if val, ok := EncryptionTypeById[eType]; ok {
		return val
	}

	return fmt.Sprintf("unknow-etype-%d", eType)
}

var EncryptionTypeById = map[int32]string{
	DES_CBC_CRC: "des-cbc-crc",
	DES_CBC_MD4: "des-cbc-md4",
	DES_CBC_MD5: "des-cbc-md5",
	// DES_CBC_RAW:                  "des-cbc-raw",
	DES3_CBC_MD5: "des3-cbc-md5",
	// DES3_CBC_RAW:                 "des3-cbc-raw",
	DES3_CBC_SHA1: "des3-cbc-sha1",
	// DES_HMAC_SHA1:                "des3-hmac-sha1",
	DES3_CBC_SHA1_KD:             "des3-cbc-sha1-kd",
	DSAWITHSHA1_CMSOID:           "dsaWithSHA1-CmsOID",
	MD5WITHRSAENCRYPTION_CMSOID:  "md5WithRSAEncryption-CmsOID",
	SHA1WITHRSAENCRYPTION_CMSOID: "sha1WithRSAEncryption-CmsOID",
	RC2CBC_ENVOID:                "rc2CBC-EnvOID",
	RSAENCRYPTION_ENVOID:         "rsaEncryption-EnvOID",
	RSAES_OAEP_ENV_OID:           "rsaES-OAEP-ENV-OID",
	DES_EDE3_CBC_ENV_OID:         "des-ede3-cbc-Env-OID",
	AES128_CTS_HMAC_SHA1_96:      "aes128-cts-hmac-sha1-96",
	AES256_CTS_HMAC_SHA1_96:      "aes256-cts-hmac-sha1-96",
	// AES128_CTS_HMAC_SHA256_128:   "aes128-cts-hmac-sha256-128",
	// AES256_CTS_HMAC_SHA384_192:   "aes256-cts-hmac-sha384-192",
	RC4_HMAC:     "arcfour-hmac-md5",
	RC4_HMAC_EXP: "arcfour-hmac-md5-exp",
	// CAMELLIA128_CTS_CMAC:         "camellia128-cts-cmac",
	// CAMELLIA256_CTS_CMAC:         "camellia256-cts-cmac",
	SUBKEY_KEYMATERIAL: "subkey-keymaterial",
}

type etype struct {
	eType         int32
	secretKeySize int
	hashFunc      (func() hash.Hash)
	hmacSize      int
	blockSize     int
	cipherFunc    (func([]byte) (cipher.Block, error))
}

func NewEType(eType int32) (rfc3961.EncryptionType, error) {
	if eType == RC4_HMAC {
		return (rfc3961.EncryptionType)(etype{
			eType:         eType,
			secretKeySize: 0,
			hashFunc:      nil,
			hmacSize:      0,
			blockSize:     0,
			cipherFunc:    nil,
		}), nil
	} else if eType == AES128_CTS_HMAC_SHA1_96 {
		return (rfc3961.EncryptionType)(etype{
			eType:         eType,
			secretKeySize: 128,
			hashFunc:      sha1.New,
			hmacSize:      96,
			blockSize:     aes.BlockSize,
			cipherFunc:    aes.NewCipher,
		}), nil
	} else if eType == AES256_CTS_HMAC_SHA1_96 {
		return (rfc3961.EncryptionType)(etype{
			eType:         eType,
			secretKeySize: 256,
			hashFunc:      sha1.New,
			hmacSize:      96,
			blockSize:     aes.BlockSize,
			cipherFunc:    aes.NewCipher,
		}), nil
	}

	return nil, fmt.Errorf("Unsupported cipher with etype %d", eType)
}

func (c etype) String() string {
	return ETypeToString(c.GetEtype())
}

func (c etype) GetEtype() int32 {
	return c.eType
}

func (c etype) GetHashFunc() func() hash.Hash {
	return c.hashFunc
}

func (c etype) GetHmacSize() int {
	return c.hmacSize / 8
}

func (c etype) GetCipherBlockSize() int {
	return c.blockSize
}

func (c etype) Encrypt(key []byte, data []byte) ([]byte, error) {
	if c.eType == RC4_HMAC {
		return rfc4757.Encrypt(key, data)
	} else {
		return crypto_aes.CTSEncrypt(key, data)
	}
}

func (c etype) EncryptMessage(key []byte, clearMessage []byte, usage uint32) ([]byte, error) {
	if c.eType == RC4_HMAC {
		return rfc4757.EncryptMessage(key, clearMessage, usage)
	} else {
		return rfc3961.EncryptMessage(c, key, clearMessage, usage)
	}
}

func (c etype) Decrypt(key []byte, data []byte) ([]byte, error) {
	if c.eType == RC4_HMAC {
		return rfc4757.Decrypt(key, data)
	} else {
		return crypto_aes.CTSDecrypt(key, data)
	}
}

func (c etype) DecryptMessage(key []byte, encryptedMessage []byte, usage uint32) ([]byte, error) {
	if c.eType == RC4_HMAC {
		return rfc4757.DecryptMessage(key, encryptedMessage, usage)
	} else {
		return rfc3961.DecryptMessage(c, key, encryptedMessage, usage)
	}
}

func (c etype) GetSecretKeySize() int {
	return c.secretKeySize / 8
}

func (c etype) GenerateSecretkey(password string, salt string, s2kparams string) ([]byte, error) {
	if c.eType == RC4_HMAC {
		return rfc4757.StringToKey(password)
	} else {
		return rfc3962.StringToKey(password, salt, s2kparams, c)
	}
}
