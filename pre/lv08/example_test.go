package lv08_test

import (
	"fmt"
	"log"

	"github.com/etclab/ncircl/pre/lv08"
	"github.com/etclab/ncircl/util/blspairing"
)

func Example() {
	pp := lv08.NewPublicParams()

	alicePK, aliceSK := lv08.KeyGen(pp)
	bobPK, bobSK := lv08.KeyGen(pp)

	rkAliceToBob := lv08.ReEncryptionKeyGen(pp, aliceSK, bobPK)

	msg := blspairing.NewRandomGt()
	ct2 := lv08.Encrypt2(pp, alicePK, msg)

	ct1, err := lv08.ReEncrypt(pp, rkAliceToBob, ct2)
	if err != nil {
		log.Fatalf("lv08.ReEncrypt failed: %v", err)
	}

	got, err := lv08.Decrypt1(pp, bobSK, ct1)
	if err != nil {
		log.Fatalf("lv08.Decrypt1 failed: %v", err)
	}

	fmt.Println(got.IsEqual(msg))
	// Output:
	// true
}
