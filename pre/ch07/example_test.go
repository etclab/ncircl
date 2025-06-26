package ch07_test

import (
	"fmt"
	"log"

	"github.com/etclab/ncircl/pre/ch07"
	"github.com/etclab/ncircl/util/blspairing"
)

func Example() {
	pp := ch07.NewPublicParams()

	alicePK, aliceSK := ch07.KeyGen(pp)
	bobPK, bobSK := ch07.KeyGen(pp)

	rkAliceToBob := ch07.ReEncryptionKeyGen(pp, aliceSK, bobSK)

	msg := blspairing.NewRandomGt()

	ct := ch07.Encrypt(pp, alicePK, msg)
	err := ch07.ReEncrypt(pp, rkAliceToBob, bobPK, ct)
	if err != nil {
		log.Fatalf("ReEncrypt failed: %v", err)
	}

	got, err := ch07.Decrypt(pp, bobSK, ct)
	if err != nil {
		log.Fatalf("Encrypt failed: %v", err)
	}

	fmt.Println(got.IsEqual(msg))
	// Output:
	// true
}
