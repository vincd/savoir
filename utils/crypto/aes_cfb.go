// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// CFB (Cipher Feedback) Mode.

package crypto

import (
	"crypto/cipher"
)

type cfb struct {
	b             cipher.Block
	shiftRegister []byte
	segmentSize   int
	decrypt       bool
}

func (x *cfb) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}

	for i := 0; i < len(src); i += x.segmentSize {
		cipher_segment := src[i : i+x.segmentSize]
		xor_segment := make([]byte, x.b.BlockSize())
		x.b.Encrypt(xor_segment, x.shiftRegister)

		for j := 0; j < x.segmentSize; j++ {
			dst[i+j] = xor_segment[j] ^ cipher_segment[j]
		}

		x.shiftRegister = append(x.shiftRegister[x.segmentSize:], cipher_segment[:x.segmentSize]...)
	}
}

// NewCFBEncrypter returns a Stream which encrypts with cipher feedback mode,
// using the given Block. The iv must be the same length as the Block's block
// size.
func NewCFBEncrypter(block cipher.Block, iv []byte) cipher.Stream {
	return newCFB(block, iv, false)
}

// NewCFBDecrypter returns a Stream which decrypts with cipher feedback mode,
// using the given Block. The iv must be the same length as the Block's block
// size.
func NewCFBDecrypter(block cipher.Block, iv []byte) cipher.Stream {
	return newCFB(block, iv, true)
}

func newCFB(block cipher.Block, iv []byte, decrypt bool) cipher.Stream {
	blockSize := block.BlockSize()
	if len(iv) != blockSize {
		// stack trace will indicate whether it was de or encryption
		panic("cipher.newCFB: IV length must equal block size")
	}
	x := &cfb{
		b:             block,
		shiftRegister: make([]byte, blockSize),
		segmentSize:   1,
		decrypt:       decrypt,
	}
	copy(x.shiftRegister, iv)

	return x
}
