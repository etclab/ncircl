package bgls03

import (
	"fmt"
	"testing"

	"github.com/etclab/ncircl/util/bytesx"
)

func TestSign(t *testing.T) {
	m := []byte("The quick brown fox jumps over the lazy dog.")
	pp := NewPublicParams()
	pk, sk := KeyGen(pp)
	sig := Sign(pp, sk, m, nil)
	err := Verify(pp, []*PublicKey{pk}, [][]byte{m}, sig)
	if err != nil {
		t.Fatalf("expected Verify to return nil; go an error: %v", err)
	}
}

func TestSignInitialSignature(t *testing.T) {
	m := []byte("The quick brown fox jumps over the lazy dog.")
	pp := NewPublicParams()
	pk, sk := KeyGen(pp)
    sigA := NewSignature()
	sigB := Sign(pp, sk, m, sigA)

    if sigA != sigB
        t.Fatal("Sign: return value is not the same address as the in-out signature parameter")
    }

	err := Verify(pp, []*PublicKey{pk}, [][]byte{m}, sigA)
	if err != nil {
		t.Fatalf("expected Verify to return nil; go an error: %v", err)
	}
}

func TestVerifyInvalid(t *testing.T) {
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

func TestManySign(t *testing.T) {
	aliceMsg := []byte("Alice's message")
	bobMsg := []byte("Bob's message")
	carolMsg := []byte("Carol's message")
	msgs := [][]byte{aliceMsg, bobMsg, carolMsg}

	pp := NewPublicParams()

	alicePK, aliceSK := KeyGen(pp)
	bobPK, bobSK := KeyGen(pp)
	carolPK, carolSK := KeyGen(pp)
	pks := []*PublicKey{alicePK, bobPK, carolPK}

	aggSig := NewSignature()
	Sign(pp, aliceSK, aliceMsg, aggSig)
	Sign(pp, bobSK, bobMsg, aggSig)
	Sign(pp, carolSK, carolMsg, aggSig)

	err := Verify(pp, pks, msgs, aggSig)
	if err != nil {
		t.Fatalf("expected Verify to return nil; go an error: %v", err)
	}
}

func TestAggregate(t *testing.T) {
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

const (
	benchmarkMsgSize       = 1024 // 1 KiB
	benchmarkMaxSignatures = 1024 // 2^10
)

type user struct {
	pk  *PublicKey
	sk  *PrivateKey
	msg []byte
	sig *Signature
}

func newUser(pp *PublicParams) *user {
	u := new(user)
	u.pk, u.sk = KeyGen(pp)
	u.msg = bytesx.Random(benchmarkMsgSize)
	u.sig = Sign(pp, u.sk, u.msg, nil)
	return u
}

func BenchmarkKeyGen(b *testing.B) {
	pp := NewPublicParams()
	for b.Loop() {
		_, _ = KeyGen(pp)
	}
}

func BenchmarkSign(b *testing.B) {
	pp := NewPublicParams()

	var aggSigs []*Signature
    aggSig := NewSignature()
	for n := 1; n <= benchmarkMaxSignatures; n++ {
		_, sk := KeyGen(pp)
		msg := bytesx.Random(benchmarkMsgSize)
		Sign(pp, sk, msg, aggSig)
		aggSigs = append(aggSigs, aggSig.Clone())
	}

	b.Run("numPrevSigs:0", func(b *testing.B) {
		_, sk := KeyGen(pp)
		msg := bytesx.Random(benchmarkMsgSize)
		for b.Loop() {
			Sign(pp, sk, msg, nil)
		}
	})

	for n := 1; n <= benchmarkMaxSignatures; n *= 2 {
		b.Run(fmt.Sprintf("numPrevSigs:%d", n), func(b *testing.B) {
			_, sk := KeyGen(pp)
			msg := bytesx.Random(benchmarkMsgSize)
			for b.Loop() {
                b.StopTimer()
                aggSig := aggSigs[n-1].Clone()
                b.StartTimer()
				Sign(pp, sk, msg, aggSig)
			}
		})
	}
}

func BenchmarkAggregate(b *testing.B) {
	pp := NewPublicParams()

	var sigs []*Signature
	for n := 1; n <= benchmarkMaxSignatures; n++ {
		u := newUser(pp)
		sigs = append(sigs, u.sig)
	}

	for n := 1; n <= benchmarkMaxSignatures; n *= 2 {
		b.Run(fmt.Sprintf("numSigs:%d", n), func(b *testing.B) {
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
	for n := 1; n <= benchmarkMaxSignatures; n++ {
		u := newUser(pp)
		sigs = append(sigs, u.sig)
		msgs = append(msgs, u.msg)
		pks = append(pks, u.pk)
	}

	for n := 1; n <= benchmarkMaxSignatures; n *= 2 {
		b.Run(fmt.Sprintf("numSigs:%d", n), func(b *testing.B) {
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
