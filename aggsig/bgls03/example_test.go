package bgls03_test

import (
	"fmt"

	"github.com/etclab/ncircl/aggsig/bgls03"
)

func ExampleSign() {
	aliceMsg := []byte("Alice's message")
	bobMsg := []byte("Bob's message")
	carolMsg := []byte("Carol's message")
	msgs := [][]byte{aliceMsg, bobMsg, carolMsg}

	pp := bgls03.NewPublicParams()

	alicePK, aliceSK := bgls03.KeyGen(pp)
	bobPK, bobSK := bgls03.KeyGen(pp)
	carolPK, carolSK := bgls03.KeyGen(pp)
	pks := []*bgls03.PublicKey{alicePK, bobPK, carolPK}

    aggSig := bgls03.NewSignature()
	bgls03.Sign(pp, aliceSK, aliceMsg, aggSig)
	bgls03.Sign(pp, bobSK, bobMsg, aggSig)
	bgls03.Sign(pp, carolSK, carolMsg, aggSig)

	err := bgls03.Verify(pp, pks, msgs, aggSig)
	fmt.Println(err)
	// Output:
	// <nil>
}

func ExampleAggregate() {
	aliceMsg := []byte("Alice's message")
	bobMsg := []byte("Bob's message")
	carolMsg := []byte("Carol's message")
	msgs := [][]byte{aliceMsg, bobMsg, carolMsg}

	pp := bgls03.NewPublicParams()

	alicePK, aliceSK := bgls03.KeyGen(pp)
	bobPK, bobSK := bgls03.KeyGen(pp)
	carolPK, carolSK := bgls03.KeyGen(pp)
	pks := []*bgls03.PublicKey{alicePK, bobPK, carolPK}

	aliceSig := bgls03.Sign(pp, aliceSK, aliceMsg, nil)
	bobSig := bgls03.Sign(pp, bobSK, bobMsg, nil)
	carolSig := bgls03.Sign(pp, carolSK, carolMsg, nil)

	allSigs := []*bgls03.Signature{aliceSig, bobSig, carolSig}
	aggSig := bgls03.Aggregate(pp, allSigs)

	err := bgls03.Verify(pp, pks, msgs, aggSig)
	fmt.Println(err)
	// Output:
	// <nil>
}
