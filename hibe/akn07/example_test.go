package akn07_test

import (
	"fmt"
	"log"

	"github.com/etclab/ncircl/hibe/akn07"
	"github.com/etclab/ncircl/util/aesx"
	"github.com/etclab/ncircl/util/blspairing"
	"github.com/etclab/ncircl/util/bytesx"
)

// Example shows how Bob would encrypt a messsage to Alice, and how Alice would
// decrypt the message.
func ExampleEncrypt() {
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

// We assume the sender and receiver have the same pattern (or, more generally,
// can derive the same pattern).  The sender uses akn07 to encrypt a random Gt,
// which is then passed to a KDF to generate an AES-256 key.  The AES key
// encrypts the message "The lazy dog ...".  The message that the sender
// signs is the result of hashing "The lazy dog ...." to a scalar.
func ExampleSign() {

	// setup
	patternStr := []string{"foo", "bar", "baz"}
	plaintext := []byte("The quick brown fox jumps over the lazy dog.")
	hashPlaintext := blspairing.HashBytesToScalar(plaintext)

	pp, msk := akn07.Setup(5)

	pattern, err := akn07.NewPatternFromStrings(pp, patternStr)
	if err != nil {
		log.Fatalf("failed to create pattern: %v", err)
	}

	key, err := akn07.KeyGen(pp, msk, pattern)
	if err != nil {
		log.Fatalf("failed to generate key: %v", err)
	}

	// sender
	m := blspairing.NewRandomGt()
	aesKey := blspairing.KdfGtToAes256(m)
	iv := bytesx.Random(16)
	ciphertext, err := aesx.EncryptCTR(aesKey, iv, plaintext)
	if err != nil {
		log.Fatalf("failed to AES-encrypt the message: %v", err)
	}
	ct, err := akn07.Encrypt(pp, pattern, m)
	if err != nil {
		log.Fatalf("failed to akn07-encrypt: %v", err)
	}
	sig := akn07.Sign(pp, key, hashPlaintext)

	// receiver
	got := akn07.Decrypt(pp, key, ct)
	if !got.IsEqual(m) {
		log.Fatalf("failed to akn07-decrypt")
	}

	aesKey2 := blspairing.KdfGtToAes256(got)
	plaintext2, err := aesx.DecryptCTR(aesKey2, iv, ciphertext)
	if err != nil {
		log.Fatalf("failed to AES-decrypt the message: %v", err)
	}
	hashPlaintext2 := blspairing.HashBytesToScalar(plaintext2)
	fmt.Printf("signature valid: %v\n", akn07.Verify(pp, pattern, sig, hashPlaintext2))
	fmt.Printf("message: %q\n", string(plaintext2))
	// Output:
	// signature valid: true
	// message: "The quick brown fox jumps over the lazy dog."
}
