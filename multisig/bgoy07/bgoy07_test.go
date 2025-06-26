package bgoy07

import (
	"fmt"
	"testing"

	"github.com/etclab/ncircl/util/bytesx"
)

func TestSingleSign(t *testing.T) {
	m := []byte("The quick brown fox jumps over the lazy dog.")

	pp := NewPublicParams()

	alicePK, aliceSK := KeyGen(pp)
	pubkeys := []*PublicKey{alicePK}

	sig := NewSignature()
	err := Sign(pp, aliceSK, m, sig, nil)
	if err != nil {
		t.Fatalf("Alice sign failed: %v", err)
	}

	err = Verify(pp, pubkeys, m, sig)
	if err != nil {
		t.Fatalf("expected Verify to return nil; got %v", err)
	}
}

func TestMultiSign(t *testing.T) {
	m := []byte("The quick brown fox jumps over the lazy dog.")

	pp := NewPublicParams()

	alicePK, aliceSK := KeyGen(pp)
	bobPK, bobSK := KeyGen(pp)
	carolPK, carolSK := KeyGen(pp)
	pubkeys := []*PublicKey{alicePK, bobPK, carolPK}

	muSig := NewSignature()
	err := Sign(pp, aliceSK, m, muSig, nil)
	if err != nil {
		t.Fatalf("Alice sign failed: %v", err)
	}

	err = Sign(pp, bobSK, m, muSig, pubkeys[:1])
	if err != nil {
		t.Fatalf("Bob sign failed: %v", err)
	}

	err = Sign(pp, carolSK, m, muSig, pubkeys[:2])
	if err != nil {
		t.Fatalf("Carol sign failed: %v", err)
	}

	err = Verify(pp, pubkeys, m, muSig)
	if err != nil {
		t.Fatalf("expected Verify to return nil; got %v", err)
	}
}

const (
	benchmarkMsgSize       = 1024 // 1 KiB
	benchmarkMaxSignatures = 1024 // 2^10
)

type user struct {
	pk *PublicKey
	sk *PrivateKey
}

func newUser(pp *PublicParams) *user {
	u := new(user)
	u.pk, u.sk = KeyGen(pp)
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
	var pks []*PublicKey

	muSig := NewSignature()
	for n := 1; n <= benchmarkMaxSignatures; n++ {
		u := newUser(pp)
		err := Sign(pp, u.sk, msg, muSig, pks[:n-1])
		if err != nil {
			b.Fatalf("Sign failed: %v", err)
		}
		muSigs = append(muSigs, muSig.Clone())
		pks = append(pks, u.pk)
	}

	b.Run("numPrevSigs:0", func(b *testing.B) {
		_, sk := KeyGen(pp)
		for b.Loop() {
			b.StopTimer()
			muSig := NewSignature()
			b.StartTimer()
			err := Sign(pp, sk, msg, muSig, nil)
			if err != nil {
				b.Fatalf("Sign failed: %v", err)
			}
		}
	})

	for n := 1; n <= benchmarkMaxSignatures; n *= 2 {
		b.Run(fmt.Sprintf("numPrevSigs:%d", n), func(b *testing.B) {
			_, sk := KeyGen(pp)
			for b.Loop() {
				b.StopTimer()
				muSig := muSigs[n-1].Clone()
				b.StartTimer()
				err := Sign(pp, sk, msg, muSig, pks[:n])
				if err != nil {
					b.Fatalf("Sign failed: %v", err)
				}
			}
		})
	}
}

func BenchmarkVerify(b *testing.B) {
	msg := bytesx.Random(benchmarkMsgSize)
	pp := NewPublicParams()

	var muSigs []*Signature
	var pks []*PublicKey

	var err error
	muSig := NewSignature()
	for n := 1; n <= benchmarkMaxSignatures; n++ {
		u := newUser(pp)
		err = Sign(pp, u.sk, msg, muSig, pks[:n-1])
		if err != nil {
			b.Fatalf("Sign failed: %v", err)
		}
		muSigs = append(muSigs, muSig.Clone())
		pks = append(pks, u.pk)
	}

	for n := 1; n <= benchmarkMaxSignatures; n *= 2 {
		b.Run(fmt.Sprintf("numSigs:%d", n), func(b *testing.B) {
			for b.Loop() {
				err := Verify(pp, pks[:n], msg, muSigs[n-1])
				if err != nil {
					b.Fatalf("expected Verify to return nil; got %v", err)
				}
			}
		})
	}
}
