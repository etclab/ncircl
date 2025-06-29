package bf01_test

import (
	"bytes"
	"fmt"

	"github.com/etclab/ncircl/ibe/bf01"
)

// Example shows how Bob would encrypt a messsage to Alice, and how Alice would
// decrypt the message.
func Example() {
	aliceID := []byte("alice@example.com")
	msg := []byte("The quick brown fox jumps over the lazy dog.")

	pkg, pp := bf01.NewPrivateKeyGenerator()
	aliceSK := pkg.Extract(aliceID)

	// Encrypt a message to Alice.
	ct := bf01.Encrypt(pp, aliceID, msg)

	// Alice decrypts the message.
	got := bf01.Decrypt(pp, aliceSK, ct)

	fmt.Println(bytes.Equal(msg, got))
	// Output:
	// true
}
