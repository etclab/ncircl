package bgoy06_test

import (
	"fmt"
	"log"

	"github.com/etclab/ncircl/multisig/bgoy06"
)

func Example() {
	m := []byte("The quick brown fox jumps over the lazy dog.")

	pp := bgoy06.NewPublicParams()

	alicePK, aliceSK := bgoy06.KeyGen(pp)
	bobPK, bobSK := bgoy06.KeyGen(pp)
	carolPK, carolSK := bgoy06.KeyGen(pp)
	pubkeys := []*bgoy06.PublicKey{alicePK, bobPK, carolPK}

	muSig, err := bgoy06.Sign(pp, aliceSK, m, nil, nil)
	if err != nil {
		log.Fatalf("Alice sign failed: %v", err)
	}

	_, err = bgoy06.Sign(pp, bobSK, m, muSig, pubkeys[:1])
	if err != nil {
		log.Fatalf("Bob sign failed: %v", err)
	}

	_, err = bgoy06.Sign(pp, carolSK, m, muSig, pubkeys[:2])
	if err != nil {
		log.Fatalf("Carol sign failed: %v", err)
	}

	valid := bgoy06.Verify(pp, pubkeys, m, muSig)
	fmt.Println(valid)
	// Output:
	// true
}
