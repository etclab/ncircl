package afgh05

import (
	"testing"

	"github.com/etclab/ncircl/util/blspairing"
)

func TestEncryptDecrypt1(t *testing.T) {
	pp := NewPublicParams()
	alicePK, aliceSK := KeyGen(pp)

	msg := blspairing.NewRandomGt()
	ct1 := Encrypt(pp, alicePK, msg)
	got := Decrypt1(pp, aliceSK, ct1)

	if !got.IsEqual(msg) {
		t.Fatal("Decrypt1 did not produce the original message")
	}
}

func TestEncryptReEncryptDecrypt2(t *testing.T) {
	pp := NewPublicParams()

	alicePK, aliceSK := KeyGen(pp)
	bobPK, bobSK := KeyGen(pp)

	rkAliceToBob := ReEncryptionKeyGen(pp, aliceSK, bobPK)

	msg := blspairing.NewRandomGt()

	ct1 := Encrypt(pp, alicePK, msg)
	ct2 := ReEncrypt(pp, rkAliceToBob, ct1)
	got := Decrypt2(pp, bobSK, ct2)

	if !got.IsEqual(msg) {
		t.Fatal("Decrypt2 did not produce the original message")
	}
}

func BenchmarkKeyGen(b *testing.B) {
	pp := NewPublicParams()
	for b.Loop() {
		_, _ = KeyGen(pp)
	}
}

func BenchmarkEncrypt(b *testing.B) {
	pp := NewPublicParams()
	msg := blspairing.NewRandomGt()
	alicePK, _ := KeyGen(pp)
	for b.Loop() {
		_ = Encrypt(pp, alicePK, msg)
	}
}

func BenchmarkDecrypt1(b *testing.B) {
	pp := NewPublicParams()
	msg := blspairing.NewRandomGt()
	alicePK, aliceSK := KeyGen(pp)
	ct1 := Encrypt(pp, alicePK, msg)
	for b.Loop() {
		_ = Decrypt1(pp, aliceSK, ct1)
	}
}

func BenchmarkReEncrypt(b *testing.B) {
	pp := NewPublicParams()
	_, aliceSK := KeyGen(pp)
	bobPK, _ := KeyGen(pp)
	for b.Loop() {
		_ = ReEncryptionKeyGen(pp, aliceSK, bobPK)
	}
}

func BenchmarkDecrypt2(b *testing.B) {
	pp := NewPublicParams()
	alicePK, aliceSK := KeyGen(pp)
	bobPK, bobSK := KeyGen(pp)
	rkAliceToBob := ReEncryptionKeyGen(pp, aliceSK, bobPK)

	msg := blspairing.NewRandomGt()
	ct1 := Encrypt(pp, alicePK, msg)
	ct2 := ReEncrypt(pp, rkAliceToBob, ct1)

	for b.Loop() {
		_ = Decrypt2(pp, bobSK, ct2)
	}
}
