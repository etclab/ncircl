package bgoy07_test

import (
	"fmt"
	"log"

	"github.com/etclab/ncircl/multisig/bgoy07"
)

func Example() {
	m := []byte("The quick brown fox jumps over the lazy dog.")

	pp := bgoy07.NewPublicParams()

	alicePK, aliceSK := bgoy07.KeyGen(pp)
	bobPK, bobSK := bgoy07.KeyGen(pp)
	carolPK, carolSK := bgoy07.KeyGen(pp)
	pubkeys := []*bgoy07.PublicKey{alicePK, bobPK, carolPK}

	muSig := bgoy07.NewSignature()
	err := bgoy07.Sign(pp, aliceSK, m, muSig, nil)
	if err != nil {
		log.Fatalf("Alice sign failed: %v", err)
	}

	err = bgoy07.Sign(pp, bobSK, m, muSig, pubkeys[:1])
	if err != nil {
		log.Fatalf("Bob sign failed: %v", err)
	}

	err = bgoy07.Sign(pp, carolSK, m, muSig, pubkeys[:2])
	if err != nil {
		log.Fatalf("Carol sign failed: %v", err)
	}

	err = bgoy07.Verify(pp, pubkeys, m, muSig)
	fmt.Println(err)
	// Output:
	// <nil>
}
