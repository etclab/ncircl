package kklmr16

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/etclab/mu"
)

func randomAttrs(n int) []bool {
	attrs := make([]bool, n)
	var b [1]byte

	for i := 0; i < n; i++ {
		// get a random byte
		_, err := rand.Read(b[:])
		if err != nil {
			mu.Panicf("rand.Read failed: %v", err)
		}

		// extract lowest bit
		bit := b[0] & 1
		attrs[i] = mu.IntToBool(int(bit))
	}

	return attrs
}

func TestPublicKey_Verify(t *testing.T) {
	for numAttrs := 1; numAttrs < 1025; numAttrs *= 2 {
		t.Run(fmt.Sprintf("numAttrs:%d", numAttrs), func(t *testing.T) {
			pp := NewPublicParams(numAttrs)
			ca := NewCertificateAuthority(pp)
			mpk := ca.MPK()

			attrs := randomAttrs(numAttrs)
			pk, _ := ca.GenCert(attrs)

			if !pk.Verify(pp, mpk) {
				t.Fatal("pk.Verify failed")
			}
		})
	}
}
