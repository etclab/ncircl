package kklmr16

import (
	"fmt"
	"testing"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/etclab/ncircl/util/blspairing"
	"github.com/etclab/ncircl/util/boolx"
)

func TestMarshalPublicKey(t *testing.T) {
	for numAttrs := 1; numAttrs < 1025; numAttrs *= 2 {
		t.Run(fmt.Sprintf("numAttrs:%d", numAttrs), func(t *testing.T) {
			pp := NewPublicParams(numAttrs)
			ca := NewCertificateAuthority(pp)
			pk, _ := ca.GenCert(boolx.Random(numAttrs))

			data, err := pk.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}

			pk2 := new(PublicKey)
			if err := pk2.UnmarshalBinary(data); err != nil {
				t.Fatal(err)
			}

			if !pk.IsEqual(pk2) {
				t.Fatal("pk.IsEqual failed")
			}
		})
	}
}

func TestMarshalPrivateKey(t *testing.T) {
	for numAttrs := 1; numAttrs < 1025; numAttrs *= 2 {
		t.Run(fmt.Sprintf("numAttrs:%d", numAttrs), func(t *testing.T) {
			pp := NewPublicParams(numAttrs)
			ca := NewCertificateAuthority(pp)
			_, sk := ca.GenCert(boolx.Random(numAttrs))

			data, err := sk.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}

			sk2 := new(PrivateKey)
			if err := sk2.UnmarshalBinary(data); err != nil {
				t.Fatal(err)
			}

			if !sk.IsEqual(sk2) {
				t.Fatal("sk.IsEqual failed")
			}
		})
	}
}

func TestMarshalMasterPublicKey(t *testing.T) {
	for numAttrs := 1; numAttrs < 1025; numAttrs *= 2 {
		t.Run(fmt.Sprintf("numAttrs:%d", numAttrs), func(t *testing.T) {
			pp := NewPublicParams(numAttrs)
			ca := NewCertificateAuthority(pp)
			mpk := ca.MPK()

			data, err := mpk.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}

			mpk2 := new(MPK)
			if err := mpk2.UnmarshalBinary(data); err != nil {
				t.Fatal(err)
			}

			if !mpk.IsEqual(mpk2) {
				t.Fatal("mpk.IsEqual failed")
			}
		})
	}
}

func TestMarshalCipherText(t *testing.T) {
	for numAttrs := 1; numAttrs < 1025; numAttrs *= 2 {
		t.Run(fmt.Sprintf("numAttrs:%d", numAttrs), func(t *testing.T) {
			pp := NewPublicParams(numAttrs)
			ca := NewCertificateAuthority(pp)

			attrs := boolx.Random(numAttrs)
			pk, _ := ca.GenCert(attrs)

			// generate random plaintext
			pt := make([]*bls.G1, pp.NumAttrs*2)
			for i := 0; i < len(pt); i++ {
				pt[i] = blspairing.NewRandomG1()
			}

			ct := Encrypt(pp, pk, nil, pt)

			data, err := ct.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}

			ct2 := new(Ciphertext)
			if err := ct2.UnmarshalBinary(data); err != nil {
				t.Fatal(err)
			}

			if !ct.IsEqual(ct2) {
				t.Fatal("ct.IsEqual failed")
			}
		})
	}
}

func TestPublicKey_Verify(t *testing.T) {
	for numAttrs := 1; numAttrs < 1025; numAttrs *= 2 {
		t.Run(fmt.Sprintf("numAttrs:%d", numAttrs), func(t *testing.T) {
			pp := NewPublicParams(numAttrs)
			ca := NewCertificateAuthority(pp)
			mpk := ca.MPK()

			attrs := boolx.Random(numAttrs)
			pk, _ := ca.GenCert(attrs)

			if !pk.Verify(pp, mpk) {
				t.Fatal("pk.Verify failed")
			}
		})
	}
}

func TestEncryptDecrypt(t *testing.T) {
	numAttrs := 2
	pp := NewPublicParams(numAttrs)
	ca := NewCertificateAuthority(pp)

	attrs := []bool{false, true}
	pk, sk := ca.GenCert(attrs)

	// generate random plaintext
	pt := make([]*bls.G1, pp.NumAttrs*2)
	for i := 0; i < len(pt); i++ {
		pt[i] = blspairing.NewRandomG1()
	}

	ct := Encrypt(pp, pk, nil, pt)
	got := Decrypt(pp, sk, ct)

	if !got[0].IsEqual(pt[0]) {
		t.Error("expected got[0] to equal pt[0]")
	}

	if !got[1].IsEqual(pt[3]) {
		t.Error("expected got[0] to equal pt[3]")
	}
}

func TestEncryptDecryptVaryAttrs(t *testing.T) {
	for numAttrs := 1; numAttrs < 1025; numAttrs *= 2 {
		t.Run(fmt.Sprintf("numAttrs:%d", numAttrs), func(t *testing.T) {
			pp := NewPublicParams(numAttrs)
			ca := NewCertificateAuthority(pp)

			attrs := boolx.Random(numAttrs)
			pk, sk := ca.GenCert(attrs)

			// generate random plaintext
			pt := make([]*bls.G1, pp.NumAttrs*2)
			for i := 0; i < len(pt); i++ {
				pt[i] = blspairing.NewRandomG1()
			}

			ct := Encrypt(pp, pk, nil, pt)
			got := Decrypt(pp, sk, ct)

			for i, attr := range attrs {
				if attr {
					if !got[i].IsEqual(pt[2*i+1]) {
						t.Errorf("expected got[%d] to equal pt[%d]", i, 2*i+1)
					}
				} else {
					if !got[i].IsEqual(pt[2*i]) {
						t.Errorf("expected got[%d] to equal pt[%d]", i, 2*i)
					}
				}
			}
		})
	}
}

func BenchmarkGenCert(b *testing.B) {
	for numAttrs := 1; numAttrs < 1025; numAttrs *= 2 {
		b.Run(fmt.Sprintf("numAttrs:%d", numAttrs), func(b *testing.B) {
			pp := NewPublicParams(numAttrs)
			ca := NewCertificateAuthority(pp)
			attrs := boolx.Random(numAttrs)

			for b.Loop() {
				_, _ = ca.GenCert(attrs)
			}
		})
	}
}

func BenchmarkPublicKey_Verify(b *testing.B) {
	for numAttrs := 1; numAttrs < 1025; numAttrs *= 2 {
		b.Run(fmt.Sprintf("numAttrs:%d", numAttrs), func(b *testing.B) {
			pp := NewPublicParams(numAttrs)
			ca := NewCertificateAuthority(pp)
			mpk := ca.MPK()

			attrs := boolx.Random(numAttrs)
			pk, _ := ca.GenCert(attrs)

			for b.Loop() {
				if !pk.Verify(pp, mpk) {
					b.Fatal("pk.Verify failed")
				}
			}
		})
	}
}

func BenchmarkEncrypt(b *testing.B) {
	for numAttrs := 1; numAttrs < 1025; numAttrs *= 2 {
		b.Run(fmt.Sprintf("numAttrs:%d", numAttrs), func(b *testing.B) {
			pp := NewPublicParams(numAttrs)
			ca := NewCertificateAuthority(pp)

			attrs := boolx.Random(numAttrs)
			pk, _ := ca.GenCert(attrs)

			// generate random plaintext
			pt := make([]*bls.G1, pp.NumAttrs*2)
			for i := 0; i < len(pt); i++ {
				pt[i] = blspairing.NewRandomG1()
			}

			for b.Loop() {
				_ = Encrypt(pp, pk, nil, pt)
			}
		})
	}
}

func BenchmarkDecrypt(b *testing.B) {
	for numAttrs := 1; numAttrs < 1025; numAttrs *= 2 {
		b.Run(fmt.Sprintf("numAttrs:%d", numAttrs), func(b *testing.B) {
			pp := NewPublicParams(numAttrs)
			ca := NewCertificateAuthority(pp)

			attrs := boolx.Random(numAttrs)
			pk, sk := ca.GenCert(attrs)

			// generate random plaintext
			pt := make([]*bls.G1, pp.NumAttrs*2)
			for i := 0; i < len(pt); i++ {
				pt[i] = blspairing.NewRandomG1()
			}
			ct := Encrypt(pp, pk, nil, pt)

			for b.Loop() {
				_ = Decrypt(pp, sk, ct)
			}
		})
	}
}
