package aesx

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

var (
	ErrInputNotBlockSized = errors.New("aesx: input buffer is not a multiple of the block size")
	ErrOutputBufSize      = errors.New("aesx: output buffer does not equal input buffer size")
)

type ECB struct {
	key []byte
	blk cipher.Block
}

func NewECB(key []byte) (*ECB, error) {
	ecb, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &ECB{blk: ecb, key: bytes.Clone(key)}, nil
}

func (ecb *ECB) Encrypt(dst, src []byte) error {
	if len(src)%ecb.blk.BlockSize() != 0 {
		return ErrInputNotBlockSized
	}

	if len(src) != len(dst) {
		return ErrOutputBufSize
	}

	for bs, be := 0, ecb.blk.BlockSize(); bs < len(src); bs, be = bs+ecb.blk.BlockSize(), be+ecb.blk.BlockSize() {
		ecb.blk.Encrypt(dst[bs:be], src[bs:be])
	}

	return nil
}

func (ecb *ECB) Decrypt(dst, src []byte) error {
	if len(src)%ecb.blk.BlockSize() != 0 {
		return ErrInputNotBlockSized
	}

	if len(src) != len(dst) {
		return ErrOutputBufSize
	}

	for bs, be := 0, ecb.blk.BlockSize(); bs < len(src); bs, be = bs+ecb.blk.BlockSize(), be+ecb.blk.BlockSize() {
		ecb.blk.Decrypt(dst[bs:be], src[bs:be])
	}

	return nil
}

func EncryptECB(key, dst []byte, src []byte) error {
	ecb, err := NewECB(key)
	if err != nil {
		return err
	}

	return ecb.Encrypt(dst, src)
}

func DecryptECB(key, dst, src []byte) error {
	ecb, err := NewECB(key)
	if err != nil {
		return err
	}

	return ecb.Decrypt(dst, src)
}

// NewGTR creates a [cipher.Stream] for AES CTR mode.
func NewCTR(key []byte, iv []byte) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCTR(block, iv), nil
}

// DoCTR performs a one-shot AES-256 CTR operation on data. The function reuses
// the data slice for the output.  As a convenience, this function also returns
// the output slice.
func DoCTR(key, iv, data []byte) ([]byte, error) {
	aesctr, err := NewCTR(key, iv)
	if err != nil {
		return nil, err
	}
	aesctr.XORKeyStream(data, data)
	return data, nil
}

// EncryptCTR performs a one-shot AES-256 CTR encryption of the plaintext data.
// This function reuses the data slice for the ciphertext.  Thus, on return,
// the plaintext is ovewritten with the ciphertext.  As a convenience, this
// function also returns the output slice.
func EncryptCTR(key, iv, data []byte) ([]byte, error) {
	return DoCTR(key, iv, data)
}

// EncryptCTR performs a one-shot AES-256 CTR decryption of the ciphertext
// data.  This function reuses the data slice for the plaintext.  Thus, on
// return, the ciphertext is ovewritten with the plaintext.  As a convenience,
// this function also returns the slice.
func DecryptCTR(key, iv, data []byte) ([]byte, error) {
	return DoCTR(key, iv, data)
}
