package afgh05_test

import (
	"fmt"

	"github.com/etclab/ncircl/pre/afgh05"
	"github.com/etclab/ncircl/util/blspairing"
)

func Example() {
	pp := afgh05.NewPublicParams()

	alicePK, aliceSK := afgh05.KeyGen(pp)
	bobPK, bobSK := afgh05.KeyGen(pp)

	rkAliceToBob := afgh05.ReEncryptionKeyGen(pp, aliceSK, bobPK)

	msg := blspairing.NewRandomGt()

	ct1 := afgh05.Encrypt(pp, alicePK, msg)
	ct2 := afgh05.ReEncrypt(pp, rkAliceToBob, ct1)
	got := afgh05.Decrypt2(pp, bobSK, ct2)

	fmt.Println(got.IsEqual(msg))
	// Output:
	// true
}
