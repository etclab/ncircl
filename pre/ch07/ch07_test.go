package ch07

import (
	"testing"

	"github.com/etclab/ncircl/util/blspairing"
)

func TestEncryptDecrypt(t *testing.T) {
	pp := NewPublicParams()
	alicePK, aliceSK := KeyGen(pp)
	msg := blspairing.NewRandomGt()
	ct := Encrypt(pp, alicePK, msg)
	got, err := Decrypt(pp, aliceSK, ct)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if !msg.IsEqual(got) {
		t.Fatal("result of decryption does not equal original message")
	}
}

func TestEncryptReEncryptDecrypt(t *testing.T) {
	pp := NewPublicParams()
	alicePK, aliceSK := KeyGen(pp)
	bobPK, bobSK := KeyGen(pp)
	rkAliceToBob := ReEncryptionKeyGen(pp, aliceSK, bobSK)

	msg := blspairing.NewRandomGt()
	ctAlice := Encrypt(pp, alicePK, msg)

	ctBob, err := ReEncrypt(pp, rkAliceToBob, bobPK, ctAlice)
	if err != nil {
		t.Fatalf("ReEncrypt failed: %v", err)
	}

	got, err := Decrypt(pp, bobSK, ctBob)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if !msg.IsEqual(got) {
		t.Fatal("result of decryption does not equal original message")
	}
}

func BenchmarkKeyGen(b *testing.B) {
	pp := NewPublicParams()
	for b.Loop() {
		_, _ = KeyGen(pp)
	}
}

func BenchmarkReEncryptKeyGen(b *testing.B) {
	pp := NewPublicParams()
	_, aliceSK := KeyGen(pp)
	_, bobSK := KeyGen(pp)
	for b.Loop() {
		_ = ReEncryptionKeyGen(pp, aliceSK, bobSK)
	}
}

func BenchmarkEncrypt(b *testing.B) {
	pp := NewPublicParams()
	alicePK, _ := KeyGen(pp)
	msg := blspairing.NewRandomGt()
	for b.Loop() {
		_ = Encrypt(pp, alicePK, msg)
	}
}

func BenchmarkReEncrypt(b *testing.B) {
	pp := NewPublicParams()
	alicePK, aliceSK := KeyGen(pp)
	bobPK, bobSK := KeyGen(pp)
	rkAliceToBob := ReEncryptionKeyGen(pp, aliceSK, bobSK)

	msg := blspairing.NewRandomGt()
	ctAlice := Encrypt(pp, alicePK, msg)

	for b.Loop() {
		_, err := ReEncrypt(pp, rkAliceToBob, bobPK, ctAlice)
		if err != nil {
			b.Fatalf("ReEncrypt failed: %v", err)
		}
	}
}

func BenchmarkDecrypt(b *testing.B) {
	pp := NewPublicParams()
	alicePK, aliceSK := KeyGen(pp)
	msg := blspairing.NewRandomGt()
	ct := Encrypt(pp, alicePK, msg)

	for b.Loop() {
		_, err := Decrypt(pp, aliceSK, ct)
		if err != nil {
			b.Fatalf("Decrypt failed: %v", err)
		}
	}
}
