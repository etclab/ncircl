package akn07_test

import (
	"fmt"
	"log"

	"github.com/etclab/ncircl/hibe/akn07"
	"github.com/etclab/ncircl/util/blspairing"
)

// Example shows how Bob would encrypt a messsage to Alice, and how Alice would
// decrypt the message.
func Example() {
	alice := []string{"com", "example", "alice"}

	pp, msk := akn07.Setup(5)

	alicePattern, err := akn07.NewPatternFromStrings(pp, alice)
	if err != nil {
		log.Fatalf("failed to create pattern: %v", err)
	}

	aliceKey, err := akn07.KeyGen(pp, msk, alicePattern)
	if err != nil {
		log.Fatalf("failed to generate key: %v", err)
	}

	m := blspairing.NewRandomGt()
	ct, err := akn07.Encrypt(pp, alicePattern, m)
	if err != nil {
		log.Fatalf("failed to encrypt: %v", err)
	}

	got := akn07.Decrypt(pp, aliceKey, ct)
	if got.IsEqual(m) {
		fmt.Printf("decryption succeeded!")
	} else {
		log.Fatalf("decryption failed")
	}
	// Output:
	// decryption succeeded!
}
