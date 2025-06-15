package bbs98_test

import (
	"crypto/elliptic"
	"fmt"
	"log"

	"github.com/etclab/ncircl/ecc"
	"github.com/etclab/ncircl/pre/bbs98"
)

func Example() {
	pp := bbs98.NewPublicParams(elliptic.P384())

	alicePK, aliceSK := bbs98.KeyGen(pp)
	_, bobSK := bbs98.KeyGen(pp)

	rkAliceToBob := bbs98.ReEncryptionKeyGen(pp, aliceSK, bobSK)

	msg := ecc.NewRandomPoint(pp.Curve)

	ct, err := bbs98.Encrypt(pp, alicePK, msg)
	if err != nil {
		log.Fatalf("Encrypt failed: %v\n", err)
	}

	bbs98.ReEncrypt(pp, rkAliceToBob, ct)

	got := bbs98.Decrypt(pp, bobSK, ct)

	fmt.Println(got.Equal(msg))
	// Output:
	// true
}
