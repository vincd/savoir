package crypto

// Implementation based on impacket:
// https://github.com/SecureAuthCorp/impacket/blob/1dad8f7f9fee82d63c876e781f2d2bab3975f2bb/impacket/krb5/crypto.py#L427

/*
```python
@classmethod
def basic_encrypt(cls, key, plaintext):
    assert len(plaintext) >= 16
    aes = AES.new(key.contents, AES.MODE_CBC, b'\0' * 16)
    ctext = aes.encrypt(_zeropad(bytes(plaintext), 16))
    if len(plaintext) > 16:
        # Swap the last two ciphertext blocks and truncate the
        # final block to match the plaintext length.
        lastlen = len(plaintext) % 16 or 16
        ctext = ctext[:-32] + ctext[-16:] + ctext[-32:-16][:lastlen]
    return ctext

@classmethod
def basic_decrypt(cls, key, ciphertext):
    assert len(ciphertext) >= 16
    aes = AES.new(key.contents, AES.MODE_ECB)
    if len(ciphertext) == 16:
        return aes.decrypt(ciphertext)
    # Split the ciphertext into blocks.  The last block may be partial.
    cblocks = [bytearray(ciphertext[p:p+16]) for p in range(0, len(ciphertext), 16)]
    lastlen = len(cblocks[-1])
    # CBC-decrypt all but the last two blocks.
    prev_cblock = bytearray(16)
    plaintext = b''
    for bb in cblocks[:-2]:
        plaintext += _xorbytes(bytearray(aes.decrypt(bytes(bb))), prev_cblock)
        prev_cblock = bb
    # Decrypt the second-to-last cipher block.  The left side of
    # the decrypted block will be the final block of plaintext
    # xor'd with the final partial cipher block; the right side
    # will be the omitted bytes of ciphertext from the final
    # block.
    bb = bytearray(aes.decrypt(bytes(cblocks[-2])))
    lastplaintext =_xorbytes(bb[:lastlen], cblocks[-1])
    omitted = bb[lastlen:]
    # Decrypt the final cipher block plus the omitted bytes to get
    # the second-to-last plaintext block.
    plaintext += _xorbytes(bytearray(aes.decrypt(bytes(cblocks[-1]) + bytes(omitted))), prev_cblock)
    return plaintext + lastplaintext
```
*/

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

//  Utility to dup a byte array
func dup(p []byte) []byte {
	q := make([]byte, len(p))
	copy(q, p)
	return q
}

// xor 2 byte arrays
func xorBytes(a, b []byte) []byte {
	// TODO: panic if len(a) != len(b)
	out := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		out[i] = a[i] ^ b[i]
	}

	return out
}

// Utility to dup message then encrypt it
func blockDecrypt(block cipher.Block, message []byte) []byte {
	m := dup(message)
	block.Decrypt(m, m)
	return m
}

// Return s padded with 0 bytes to a multiple of padsize.
func zeroPad(s []byte, padSize int) []byte {
	padLen := (padSize - (len(s) % padSize)) % padSize
	pad := make([]byte, padLen)
	return append(s, pad...)
}

func CTSEncrypt(key []byte, plainText []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("Cannot create AES block cipher: %s", err)
	}

	bs := block.BlockSize()
	iv := make([]byte, bs)
	mode := cipher.NewCBCEncrypter(block, iv)

	cipherText := zeroPad(dup(plainText), bs)
	mode.CryptBlocks(cipherText, cipherText)

	if len(plainText) <= bs {
		return cipherText, nil
	}

	// Swap the last two ciphertext blocks and truncate the
	// final block to match the plaintext length.
	lastBlockLen := len(plainText) % bs
	if lastBlockLen == 0 {
		lastBlockLen = bs
	}

	s1 := cipherText[:len(cipherText)-2*bs]
	s2 := cipherText[len(cipherText)-2*bs : len(cipherText)-bs]
	s3 := cipherText[len(cipherText)-bs:]

	cipherTextSwapped := make([]byte, 0)
	cipherTextSwapped = append(cipherTextSwapped, s1...)
	cipherTextSwapped = append(cipherTextSwapped, s3...)
	cipherTextSwapped = append(cipherTextSwapped, s2[:lastBlockLen]...)

	return cipherTextSwapped, nil
}

func CTSDecrypt(key []byte, cipherText []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("Cannot create AES block cipher: %s", err)
	}

	bs := block.BlockSize()
	if len(cipherText) == bs {
		return blockDecrypt(block, cipherText), nil
	}

	// Split the ciphertext into blocks.  The last block may be partial.
	blocks := make([][]byte, 0)
	lastBlockLen := bs
	for p := 0; p < len(cipherText); p += bs {
		if len(cipherText)-p < bs {
			lastBlockLen = len(cipherText) - p
		}

		blocks = append(blocks, cipherText[p:p+lastBlockLen])
	}

	// CBC-decrypt all but the last two blocks.
	prevCBlock := make([]byte, bs)
	plainText := make([]byte, 0)
	for i := 0; i < len(blocks)-2; i++ {
		plainText = append(plainText, xorBytes(blockDecrypt(block, blocks[i]), prevCBlock)...)
		prevCBlock = blocks[i]
	}

	// Decrypt the second-to-last cipher block.  The left side of
	// the decrypted block will be the final block of plaintext
	// xor'd with the final partial cipher block; the right side
	// will be the omitted bytes of ciphertext from the final
	// block.
	lastBlock := blockDecrypt(block, blocks[len(blocks)-2])
	lastPlainText := xorBytes(lastBlock[:lastBlockLen], blocks[len(blocks)-1])
	omitted := lastBlock[lastBlockLen:]

	// Decrypt the final cipher block plus the omitted bytes to get
	// the second-to-last plaintext block.
	beforeLastBlock := append(dup(blocks[len(blocks)-1]), omitted...)
	block.Decrypt(beforeLastBlock, beforeLastBlock)
	beforeLastPlainText := xorBytes(beforeLastBlock, prevCBlock)

	plainText = append(plainText, beforeLastPlainText...)
	plainText = append(plainText, lastPlainText...)

	return plainText, nil
}
