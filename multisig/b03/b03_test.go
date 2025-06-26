package b03

import (
	"fmt"
	"testing"

	"github.com/etclab/ncircl/util/bytesx"
)

func TestSign(t *testing.T) {
	msg := []byte("The quick brown fox jumps over the lazy dog.")
	pp := NewPublicParams()
	alicePK, aliceSK := KeyGen(pp)

	sig := NewSignature()
	Sign(pp, aliceSK, msg, sig)

	valid := Verify(pp, []*PublicKey{alicePK}, msg, sig)
	if !valid {
		t.Fatal("expected Verify to return true; got false")
	}
}

func TestMultiSign(t *testing.T) {
	msg := []byte("The quick brown fox jumps over the lazy dog.")
	pp := NewPublicParams()
	alicePK, aliceSK := KeyGen(pp)
	bobPK, bobSK := KeyGen(pp)
	carolPK, carolSK := KeyGen(pp)
	pks := []*PublicKey{alicePK, bobPK, carolPK}

	muSig := NewSignature()
	Sign(pp, aliceSK, msg, muSig)
	Sign(pp, bobSK, msg, muSig)
	Sign(pp, carolSK, msg, muSig)

	valid := Verify(pp, pks, msg, muSig)
	if !valid {
		t.Fatal("expected Verify to return true; got false")
	}
}

func TestAggregate(t *testing.T) {
	msg := []byte("The quick brown fox jumps over the lazy dog.")
	pp := NewPublicParams()
	alicePK, aliceSK := KeyGen(pp)
	bobPK, bobSK := KeyGen(pp)
	carolPK, carolSK := KeyGen(pp)
	pks := []*PublicKey{alicePK, bobPK, carolPK}

	aliceSig := NewSignature()
	Sign(pp, aliceSK, msg, aliceSig)

	bobSig := NewSignature()
	Sign(pp, bobSK, msg, bobSig)

	carolSig := NewSignature()
	Sign(pp, carolSK, msg, carolSig)

	allSigs := []*Signature{aliceSig, bobSig, carolSig}
	muSig := Aggregate(pp, allSigs)

	valid := Verify(pp, pks, msg, muSig)
	if !valid {
		t.Fatal("expected Verify to return true; got false")
	}
}

const (
	benchmarkMsgSize       = 1024 // 1 KiB
	benchmarkMaxSignatures = 1024 // 2^10
)

type user struct {
	pk  *PublicKey
	sk  *PrivateKey
	sig *Signature
}

func newUser(pp *PublicParams, msg []byte) *user {
	u := new(user)
	u.pk, u.sk = KeyGen(pp)
	u.sig = NewSignature()
	Sign(pp, u.sk, msg, u.sig)
	return u
}

func BenchmarkKeyGen(b *testing.B) {
	pp := NewPublicParams()
	for b.Loop() {
		_, _ = KeyGen(pp)
	}
}

func BenchmarkSign(b *testing.B) {
	msg := bytesx.Random(benchmarkMsgSize)
	pp := NewPublicParams()

	var muSigs []*Signature
	muSig := NewSignature()
	for n := 1; n <= benchmarkMaxSignatures; n++ {
		_, sk := KeyGen(pp)
		Sign(pp, sk, msg, muSig)
		muSigs = append(muSigs, muSig.Clone())
	}

	b.Run("numPrevSigs:0", func(b *testing.B) {
		_, sk := KeyGen(pp)
		for b.Loop() {
			b.StopTimer()
			sig := NewSignature()
			b.StartTimer()
			Sign(pp, sk, msg, sig)
		}
	})

	for n := 1; n <= benchmarkMaxSignatures; n *= 2 {
		b.Run(fmt.Sprintf("numPrevSigs:%d", n), func(b *testing.B) {
			_, sk := KeyGen(pp)
			for b.Loop() {
				b.StopTimer()
				muSig := muSigs[n-1].Clone()
				b.StartTimer()
				Sign(pp, sk, msg, muSig)
			}
		})
	}
}

func BenchmarkAggregate(b *testing.B) {
	msg := bytesx.Random(benchmarkMsgSize)
	pp := NewPublicParams()

	var sigs []*Signature
	for n := 1; n <= benchmarkMaxSignatures; n++ {
		u := newUser(pp, msg)
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
	msg := bytesx.Random(benchmarkMsgSize)
	pp := NewPublicParams()

	var sigs []*Signature
	var pks []*PublicKey
	for n := 1; n <= benchmarkMaxSignatures; n++ {
		u := newUser(pp, msg)
		sigs = append(sigs, u.sig)
		pks = append(pks, u.pk)
	}

	for n := 1; n <= benchmarkMaxSignatures; n *= 2 {
		b.Run(fmt.Sprintf("numSigs:%d", n), func(b *testing.B) {
			muSig := Aggregate(pp, sigs[:n])
			for b.Loop() {
				valid := Verify(pp, pks[:n], msg, muSig)
				if !valid {
					b.Fatal("expected Verify to return true; got false")
				}
			}
		})
	}
}
