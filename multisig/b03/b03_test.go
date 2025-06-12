package b03

import (
	"fmt"
	"testing"

	"github.com/etclab/ncircl/util/bytesx"
)

func TestSingleSignVerify(t *testing.T) {
	msg := []byte("The quick brown fox jumps over the lazy dog.")
	pp := NewPublicParams()
	alicePK, aliceSK := KeyGen(pp)

	sig := SingleSign(pp, aliceSK, msg)

	valid := Verify(pp, []*PublicKey{alicePK}, msg, sig)
	if !valid {
		t.Fatal("expected Verify to return true; got false")
	}
}

func TestMultiSignVerify(t *testing.T) {
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

type user struct {
	pk  *PublicKey
	sk  *PrivateKey
	sig *Signature
}

func newUser(pp *PublicParams, msg []byte) *user {
	u := new(user)
	u.pk, u.sk = KeyGen(pp)
	u.sig = SingleSign(pp, u.sk, msg)
	return u
}

func BenchmarkVerify(b *testing.B) {
	msg := bytesx.Random(64)
	pp := NewPublicParams()

	var sigs []*Signature
	var pks []*PublicKey
	for n := 1; n < 10000; n++ {
		u := newUser(pp, msg)
		sigs = append(sigs, u.sig)
		pks = append(pks, u.pk)
	}

	for n := 1; n < 10000; n *= 2 {
		b.Run(fmt.Sprintf("nsigs:%d", n), func(b *testing.B) {
			muSig := Aggregate(pp, sigs[:n])
			for b.Loop() {
				valid := Verify(pp, pks[:n], msg, muSig)
				if !valid {
					b.Fatal("expected Verfity to return true; got false")
				}
			}
		})
	}
}
