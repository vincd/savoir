package rfc3961

import (
	"github.com/vincd/savoir/utils/crypto"
)

const (
	KcOctet = byte(0x99)
	KeOctet = byte(0xAA)
	KiOctet = byte(0x55)
)

// https://datatracker.ietf.org/doc/html/RFC3961#page-16
func GetWellKnowConstant(usageNumber uint32, o byte) []byte {
	// The "well-known constant" used for the DK
	// function is the key usage number, expressed as
	// four octets in big-endian order, followed by one
	// octet indicated below.

	return []byte{
		byte(usageNumber >> 24 & 0xff),
		byte(usageNumber >> 16 & 0xff),
		byte(usageNumber >> 8 & 0xff),
		byte(usageNumber >> 0 & 0xff),
		o,
	}
}

// https://datatracker.ietf.org/doc/html/RFC3961#section-5.1
func DeriveKey(baseKey []byte, wellKnowConstant []byte, eType EncryptionType) ([]byte, error) {
	// Derived Key = DK(Base Key, Well-Known Constant)
	// DK(Key, Constant) = random-to-key(DR(Key, Constant))
	r, err := DeriveRandom(baseKey, wellKnowConstant, eType)
	if err != nil {
		return nil, err
	}

	return RandomToKey(r), nil
}

// https://datatracker.ietf.org/doc/html/RFC3961#section-5.3
func RandomToKey(b []byte) []byte {
	return b
}

func DeriveRandom(key []byte, constant []byte, eType EncryptionType) ([]byte, error) {
	// DR(Key, Constant) = k-truncate(E(Key, Constant, initial-cipher-state))

	// If the Constant is smaller than the cipher block size of E, then it
	// must be expanded with n-fold() so it can be encrypted.
	nFoldConstant := Nfold(constant, eType.GetCipherBlockSize())

	// k-truncate truncates its argument by taking the first k bits.
	ktruncate := make([]byte, eType.GetSecretKeySize())

	// K1 = E(Key, n-fold(Constant), initial-cipher-state)
	Kn, err := crypto.CTSEncrypt(key, nFoldConstant)
	if err != nil {
		return nil, err
	}

	// K2 = E(Key, K1, initial-cipher-state)
	// K3 = E(Key, K2, initial-cipher-state)
	// K4 = ...
	// DR(Key, Constant) = k-truncate(K1 | K2 | K3 | K4 ...)
	copy(ktruncate, Kn)
	for i := len(Kn); i < len(ktruncate); i += len(Kn) {
		Kn, err := crypto.CTSEncrypt(key, Kn)
		if err != nil {
			return nil, err
		}
		copy(ktruncate[i:], Kn)
	}

	return ktruncate, nil
}
