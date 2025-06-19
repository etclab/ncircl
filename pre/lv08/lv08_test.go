package lv08

import (
	"testing"

	"github.com/etclab/ncircl/util/blspairing"
)

func TestEncrypt1Decrypt1(t *testing.T) {
	pp := NewPublicParams()
	alicePK, aliceSK := KeyGen(pp)
	msg := blspairing.NewRandomGt()
	ct1 := Encrypt1(pp, alicePK, msg)
	got, err := Decrypt1(pp, aliceSK, ct1)
	if err != nil {
		t.Fatalf("Decrypt1 failed: %v", err)
	}
	if !got.IsEqual(msg) {
		t.Fatal("Decrypt1 produced a plaintext different from the original message")
	}
}

func TestEncrypt2Decrypt2(t *testing.T) {
	pp := NewPublicParams()
	alicePK, aliceSK := KeyGen(pp)
	msg := blspairing.NewRandomGt()
	ct2 := Encrypt2(pp, alicePK, msg)
	got, err := Decrypt2(pp, aliceSK, ct2)
	if err != nil {
		t.Fatalf("Decrypt2 failed: %v", err)
	}
	if !got.IsEqual(msg) {
		t.Fatal("Decrypt2 produced a plaintext different from the original message")
	}
}

func TestReEncrypt(t *testing.T) {
	pp := NewPublicParams()
	alicePK, aliceSK := KeyGen(pp)
	bobPK, bobSK := KeyGen(pp)
	rkAliceToBob := ReEncryptionKeyGen(pp, aliceSK, bobPK)

	msg := blspairing.NewRandomGt()
	ct2 := Encrypt2(pp, alicePK, msg)

	ct1, err := ReEncrypt(pp, rkAliceToBob, ct2)
	if err != nil {
		t.Fatalf("ReEncrypt failed: %v", err)
	}

	got, err := Decrypt1(pp, bobSK, ct1)
	if err != nil {
		t.Fatalf("Decrypt1 failed: %v", err)
	}
	if !got.IsEqual(msg) {
		t.Fatal("Decrypt1 produced a plaintext different from the original message")
	}
}

func BenchmarkKeyGen(b *testing.B) {
	pp := NewPublicParams()
	for b.Loop() {
		_, _ = KeyGen(pp)
	}
}

func BenchmarkReEncryptionKeyGen(b *testing.B) {
	pp := NewPublicParams()
	_, aliceSK := KeyGen(pp)
	bobPK, _ := KeyGen(pp)
	for b.Loop() {
		_ = ReEncryptionKeyGen(pp, aliceSK, bobPK)
	}
}

func BenchmarkEncrypt1(b *testing.B) {
	pp := NewPublicParams()
	msg := blspairing.NewRandomGt()
	alicePK, _ := KeyGen(pp)
	for b.Loop() {
		_ = Encrypt1(pp, alicePK, msg)
	}
}

func BenchmarkDecrypt1(b *testing.B) {
	pp := NewPublicParams()
	msg := blspairing.NewRandomGt()
	alicePK, aliceSK := KeyGen(pp)
	ct1 := Encrypt1(pp, alicePK, msg)
	for b.Loop() {
		_, err := Decrypt1(pp, aliceSK, ct1)
		if err != nil {
			b.Fatalf("Decrypt1 failed: %v", err)
		}
	}
}

func BenchmarkEncrypt2(b *testing.B) {
	pp := NewPublicParams()
	msg := blspairing.NewRandomGt()
	alicePK, _ := KeyGen(pp)
	for b.Loop() {
		_ = Encrypt2(pp, alicePK, msg)
	}

}

func BenchmarkDecrypt2(b *testing.B) {
	pp := NewPublicParams()
	msg := blspairing.NewRandomGt()
	alicePK, aliceSK := KeyGen(pp)
	ct2 := Encrypt2(pp, alicePK, msg)
	for b.Loop() {
		_, err := Decrypt2(pp, aliceSK, ct2)
		if err != nil {
			b.Fatalf("Decrypt2 failed: %v", err)
		}
	}
}

func BenchmarkReEncrypt(b *testing.B) {
	pp := NewPublicParams()
	alicePK, aliceSK := KeyGen(pp)
	bobPK, _ := KeyGen(pp)
	rkAliceToBob := ReEncryptionKeyGen(pp, aliceSK, bobPK)

	msg := blspairing.NewRandomGt()
	ct2 := Encrypt2(pp, alicePK, msg)

	for b.Loop() {
		_, err := ReEncrypt(pp, rkAliceToBob, ct2)
		if err != nil {
			b.Fatalf("ReEncrypt failed: %v", err)
		}
	}
}
