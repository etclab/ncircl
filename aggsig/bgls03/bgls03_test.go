package bgls03

import (
	"fmt"
	"testing"

	"github.com/etclab/ncircl/util/bytesx"
)

func TestSignAndVerify(t *testing.T) {
	m := []byte("The quick brown fox jumps over the lazy dog.")
	pp := NewPublicParams()
	pk, sk := KeyGen(pp)
	sig := Sign(pp, sk, m, nil)
	err := Verify(pp, []*PublicKey{pk}, [][]byte{m}, sig)
	if err != nil {
		t.Fatalf("expected Verify to return nil; go an error: %v", err)
	}
}

func TestSignAndVerifyInvalid(t *testing.T) {
	m1 := []byte("The quick brown fox jumps over the lazy dog.")
	pp := NewPublicParams()
	pk, sk := KeyGen(pp)
	sig := Sign(pp, sk, m1, nil)

	m2 := []byte("The quick brown fox jumps over the lazy cat.")
	err := Verify(pp, []*PublicKey{pk}, [][]byte{m2}, sig)
	if err == nil {
		t.Fatal("expected Verify to return an error; got nil")
	}
}

func TestSignAggregateAndVerify(t *testing.T) {
	aliceMsg := []byte("Alice's message")
	bobMsg := []byte("Bob's message")
	carolMsg := []byte("Carol's message")
	msgs := [][]byte{aliceMsg, bobMsg, carolMsg}

	pp := NewPublicParams()

	alicePK, aliceSK := KeyGen(pp)
	bobPK, bobSK := KeyGen(pp)
	carolPK, carolSK := KeyGen(pp)
	pks := []*PublicKey{alicePK, bobPK, carolPK}

	aliceSig := Sign(pp, aliceSK, aliceMsg, nil)
	bobSig := Sign(pp, bobSK, bobMsg, nil)
	carolSig := Sign(pp, carolSK, carolMsg, nil)

	sigs := []*Signature{aliceSig, bobSig, carolSig}
	aggSig := Aggregate(pp, sigs)

	err := Verify(pp, pks, msgs, aggSig)
	if err != nil {
		t.Fatalf("expected Verify to return nil; go an error: %v", err)
	}
}

func TestMessagesNotUnique(t *testing.T) {
	aliceMsg := []byte("Alice's message")
	bobMsg := []byte("Bob's message")
	carolMsg := []byte("Bob's message") // same as Bob's message
	msgs := [][]byte{aliceMsg, bobMsg, carolMsg}

	pp := NewPublicParams()

	alicePK, aliceSK := KeyGen(pp)
	bobPK, bobSK := KeyGen(pp)
	carolPK, carolSK := KeyGen(pp)
	pks := []*PublicKey{alicePK, bobPK, carolPK}

	aliceSig := Sign(pp, aliceSK, aliceMsg, nil)
	bobSig := Sign(pp, bobSK, bobMsg, nil)
	carolSig := Sign(pp, carolSK, carolMsg, nil)

	sigs := []*Signature{aliceSig, bobSig, carolSig}
	aggSig := Aggregate(pp, sigs)

	err := Verify(pp, pks, msgs, aggSig)
	if err == nil {
		t.Fatal("expected Verify to return an error; got nil")
	}
}

func BenchmarkKeyGen(b *testing.B) {
	pp := NewPublicParams()
	for b.Loop() {
		_, _ = KeyGen(pp)
	}
}

func BenchmarkSign(b *testing.B) {
	// A random 64-byte message
	msg := bytesx.Random(64)
	pp := NewPublicParams()
	_, sk := KeyGen(pp)

	for b.Loop() {
		_ = Sign(pp, sk, msg, nil)
	}
}

type user struct {
	pk  *PublicKey
	sk  *PrivateKey
	msg []byte
	sig *Signature
}

func newUser(pp *PublicParams) *user {
	u := new(user)
	u.pk, u.sk = KeyGen(pp)
	u.msg = bytesx.Random(64)
	u.sig = Sign(pp, u.sk, u.msg, nil)
	return u
}

func BenchmarkAggregate(b *testing.B) {
	pp := NewPublicParams()

	var sigs []*Signature
	for n := 1; n < 10000; n++ {
		u := newUser(pp)
		sigs = append(sigs, u.sig)
	}

	for n := 1; n < 10000; n *= 2 {
		b.Run(fmt.Sprintf("nsigs:%d", n), func(b *testing.B) {
			for b.Loop() {
				_ = Aggregate(pp, sigs[:n])
			}
		})
	}
}

func BenchmarkVerify(b *testing.B) {
	pp := NewPublicParams()

	var sigs []*Signature
	var msgs [][]byte
	var pks []*PublicKey
	for n := 1; n < 10000; n++ {
		u := newUser(pp)
		sigs = append(sigs, u.sig)
		msgs = append(msgs, u.msg)
		pks = append(pks, u.pk)
	}

	for n := 1; n < 10000; n *= 2 {
		b.Run(fmt.Sprintf("nsigs:%d", n), func(b *testing.B) {
			aggSig := Aggregate(pp, sigs[:n])
			for b.Loop() {
				err := Verify(pp, pks[:n], msgs[:n], aggSig)
				if err != nil {
					b.Fatalf("expected Verify to return nil; go an error: %v", err)
				}
			}
		})
	}

}
