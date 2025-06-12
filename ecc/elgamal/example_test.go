package elgamal_test

import (
	"crypto/elliptic"
	"fmt"
	"log"

	"github.com/etclab/ncircl/ecc"
	"github.com/etclab/ncircl/ecc/elgamal"
)

// Example shows how Bob would encrypt a messsage to Alice, and how Alice would
// decrypt the message.
func Example() {
	pp := elgamal.NewPublicParams(elliptic.P384())
	alicePK, aliceSK := elgamal.KeyGen(pp)

	// Encrypt a random curve point.  In a real use case, the point may server
	// as input to a key derivation function.
	m := ecc.NewRandomPoint(pp.Curve)
	ct, err := elgamal.Encrypt(pp, alicePK, m)
	if err != nil {
		log.Fatalf("elgamal.Encrypt failed: %v", err)
	}

	// Alice decrypts the message.
	got := elgamal.Decrypt(pp, aliceSK, ct)
	fmt.Println(got.Equal(m))
	// Output:
	// true
}
