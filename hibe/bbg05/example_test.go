package bbg05_test

import (
	"fmt"
	"log"

	"github.com/etclab/ncircl/hibe/bbg05"
	"github.com/etclab/ncircl/util/blspairing"
)

// Example shows how Bob would encrypt a messsage to Alice, and how Alice would
// decrypt the message.
func Example() {
	alice := []string{"com", "example", "alice"}
	pp, msk := bbg05.Setup(10)

	aliceId, err := bbg05.NewIdFromStrings(pp, alice)
	if err != nil {
		log.Fatalf("failed to create id: %v", err)
	}

	aliceKey, err := bbg05.KeyGen(pp, msk, aliceId)
	if err != nil {
		log.Fatalf("failed to generate key: %v", err)
	}

	m := blspairing.NewRandomGt()
	ct, err := bbg05.Encrypt(pp, aliceId, m)
	if err != nil {
		log.Fatalf("failed to encrypt: %v", err)
	}

	got := bbg05.Decrypt(pp, aliceKey, ct)
	if got.IsEqual(m) {
		fmt.Printf("decryption succeeded!")
	} else {
		log.Fatalf("decryption failed")
	}
	// Output:
	// decryption succeeded!
}
