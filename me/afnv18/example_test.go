package afnv18_test

import (
	"bytes"
	"fmt"

	"github.com/etclab/ncircl/me/afnv18"
)

// Example shows how Bob would encrypt a messsage to Alice, and how Alice would
// decrypt the message.
func Example() {
	aliceId := []byte("alice@example.com")
	bobId := []byte("bob@example.com")
	msg := []byte("The quick brown fox jumps over the lazy dog.")

	msk, pp := afnv18.Setup()
	bobSendKey := afnv18.SkGen(pp, msk, bobId)
	aliceRecvKey := afnv18.RkGen(pp, msk, aliceId)

	// Encrypt a message to Alice.
	ct := afnv18.Encrypt(pp, bobSendKey, aliceId, msg)

	// Alice decrypts the message.
	got := afnv18.Decrypt(pp, aliceRecvKey, bobId, ct)

	fmt.Println(bytes.Equal(msg, got))
	// Output:
	// true
}
