package b03_test

import (
	"fmt"

	"github.com/etclab/ncircl/multisig/b03"
)

func ExampleSign() {
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

func ExampleAggregate() {
	msg := []byte("The lazy dog jumps over the quick brown fox.")

	pp := b03.NewPublicParams()

	alicePK, aliceSK := b03.KeyGen(pp)
	bobPK, bobSK := b03.KeyGen(pp)
	carolPK, carolSK := b03.KeyGen(pp)
	pks := []*b03.PublicKey{alicePK, bobPK, carolPK}

	aliceSig := b03.NewSignature()
	b03.Sign(pp, aliceSK, msg, aliceSig)

	bobSig := b03.NewSignature()
	b03.Sign(pp, bobSK, msg, bobSig)

	carolSig := b03.NewSignature()
	b03.Sign(pp, carolSK, msg, carolSig)

	allSigs := []*b03.Signature{aliceSig, bobSig, carolSig}
	muSig := b03.Aggregate(pp, allSigs)

	valid := b03.Verify(pp, pks, msg, muSig)
	fmt.Println(valid)
	// Output:
	// true
}
