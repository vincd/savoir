package rfc3962

import (
	"crypto/sha1"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/pbkdf2"

	"github.com/vincd/savoir/modules/paquet/krb5/crypto/rfc3961"
)

// https://datatracker.ietf.org/doc/html/rfc3962

const (
	DefaultS2kParams     = int32(4096)
	DefaultS2kParamsZero = int64(4294967296)
)

func s2KParmsToIterations(s2kparams string) (int32, error) {
	// If the string-to-key parameters are not supplied, the value used is
	// 00 00 10 00 (decimal 4,096, indicating 4,096 iterations).
	// If the value is 00 00 00 00, the number of iterations to
	// be performed is 4,294,967,296 (2**32).  (Thus the minimum expressible
	// iteration count is 1.)

	if len(s2kparams) == 0 {
		return DefaultS2kParams, nil
	}

	if len(s2kparams) != 4 {
		// TODO: s2kparams might be a int64
		return int32(0), fmt.Errorf("s2kparams is not 4 bytes")
	}

	iterations := binary.BigEndian.Uint32([]byte(s2kparams))

	return int32(iterations), nil
}

func PBKDF2(passphrase string, salt string, iter_count int32, keylength int) []byte {
	// The pseudorandom function used by PBKDF2 will be a SHA-1 HMAC of the
	// passphrase and salt, as described in Appendix B.1 to PKCS#5.

	return pbkdf2.Key([]byte(passphrase), []byte(salt), int(iter_count), keylength, sha1.New)
}

func StringToKey(passphrase string, salt string, s2kparams string, eType rfc3961.EncryptionType) ([]byte, error) {
	// tkey = random2key(PBKDF2(passphrase, salt, iter_count, keylength))
	// key = DK(tkey, "kerberos")

	iter, err := s2KParmsToIterations(s2kparams)
	if err != nil {
		return nil, err
	}

	tkey := rfc3961.RandomToKey(PBKDF2(passphrase, salt, iter, eType.GetSecretKeySize()))
	key, err := rfc3961.DeriveKey(tkey, []byte("kerberos"), eType)
	if err != nil {
		return nil, err
	}

	return key, nil
}
