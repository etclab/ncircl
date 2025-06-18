package aesx

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

var (
	ErrInputNotBlockSized = errors.New("aesx: input buffer is not a multiple of the block size")
	ErrOutputBufSize      = errors.New("aesx: output buffer does not equal input buffer size")
)

type ECB struct {
	blk cipher.Block
}

func NewECB(key []byte) (*ECB, error) {
	ecb, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &ECB{blk: ecb}, nil
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
