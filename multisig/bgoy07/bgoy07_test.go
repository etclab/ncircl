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

	muSig, err := Sign(pp, aliceSK, m, nil, nil)
	if err != nil {
		t.Fatalf("Alice sign failed: %v", err)
	}

	err = Verify(pp, pubkeys, m, muSig)
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

	muSig, err := Sign(pp, aliceSK, m, nil, nil)
	if err != nil {
		t.Fatalf("Alice sign failed: %v", err)
	}

	_, err = Sign(pp, bobSK, m, muSig, pubkeys[:1])
	if err != nil {
		t.Fatalf("Bob sign failed: %v", err)
	}

	_, err = Sign(pp, carolSK, m, muSig, pubkeys[:2])
	if err != nil {
		t.Fatalf("Carol sign failed: %v", err)
	}

	err = Verify(pp, pubkeys, m, muSig)
	if err != nil {
		t.Fatalf("expected Verify to return nil; got %v", err)
	}
}

type user struct {
	pk *PublicKey
	sk *PrivateKey
}

func newUser(pp *PublicParams) *user {
	u := new(user)
	u.pk, u.sk = KeyGen(pp)
	return u
}

func BenchmarkVerify(b *testing.B) {
	msg := bytesx.Random(64)
	pp := NewPublicParams()

	var muSigs []*Signature
	var pks []*PublicKey

	muSig := NewSignature()
	for n := 1; n < 100; n++ {
		u := newUser(pp)
		_, err := Sign(pp, u.sk, msg, muSig, pks[:n-1])
		if err != nil {
			b.Fatalf("Sign failed: %v", err)
		}
		muSigs = append(muSigs, muSig.Clone())
		pks = append(pks, u.pk)
		fmt.Println(n)
	}

	for n := 1; n < 100; n *= 2 {
		b.Run(fmt.Sprintf("nsigs:%d", n), func(b *testing.B) {
			for b.Loop() {
				err := Verify(pp, pks[:n], msg, muSigs[n-1])
				if err != nil {
					b.Fatalf("expected Verify to return nil; got %v", err)
				}
			}
		})
	}
}
