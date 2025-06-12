package b03_test

import (
	"fmt"

	"github.com/etclab/ncircl/multisig/b03"
)

func Example() {
	msg := []byte("The lazy dog jumps over the quick brown fox.")

	pp := b03.NewPublicParams()

	alicePK, aliceSK := b03.KeyGen(pp)
	bobPK, bobSK := b03.KeyGen(pp)
	carolPK, carolSK := b03.KeyGen(pp)
	pks := []*b03.PublicKey{alicePK, bobPK, carolPK}

	muSig := b03.NewSignature()
	b03.Sign(pp, aliceSK, msg, muSig)
	b03.Sign(pp, bobSK, msg, muSig)
	b03.Sign(pp, carolSK, msg, muSig)

	valid := b03.Verify(pp, pks, msg, muSig)
	fmt.Println(valid)
	// Output:
	// true
}
