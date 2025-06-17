package bbs98

import (
	"crypto/elliptic"
	"testing"

	circlp384 "github.com/cloudflare/circl/ecc/p384"
	"github.com/etclab/ncircl/ecc"
)

func TestEncryptDecrypt(t *testing.T) {
	trials := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P-224", elliptic.P224()},
		{"P-256", elliptic.P256()},
		{"P-384", elliptic.P384()},
		{"P-384/circl", circlp384.P384()},
		{"P-521", elliptic.P521()},
	}

	for _, trial := range trials {
		t.Run(trial.name, func(t *testing.T) {
			pp := NewPublicParams(trial.curve)

			alicePK, aliceSK := KeyGen(pp)
			m := ecc.NewRandomPoint(trial.curve)
			ct, err := Encrypt(pp, alicePK, m)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}
			got := Decrypt(pp, aliceSK, ct)
			if !m.Equal(got) {
				t.Fatal("result of decryption does not equal original message")
			}
		})
	}
}

func TestEncryptReEncryptDecrypt(t *testing.T) {
	trials := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P-224", elliptic.P224()},
		{"P-256", elliptic.P256()},
		{"P-384", elliptic.P384()},
		{"P-384/circl", circlp384.P384()},
		{"P-521", elliptic.P521()},
	}

	for _, trial := range trials {
		t.Run(trial.name, func(t *testing.T) {
			pp := NewPublicParams(trial.curve)

			alicePK, aliceSK := KeyGen(pp)
			_, bobSK := KeyGen(pp)

			m := ecc.NewRandomPoint(trial.curve)
			ct, err := Encrypt(pp, alicePK, m)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}

			rkAliceToBob := ReEncryptionKeyGen(pp, aliceSK, bobSK)
			ReEncrypt(pp, rkAliceToBob, ct)

			got := Decrypt(pp, bobSK, ct)
			if !m.Equal(got) {
				t.Fatal("result of decryption does not equal original message")
			}
		})
	}
}

func BenchmarkKeyGen(b *testing.B) {
	trials := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P-224", elliptic.P224()},
		{"P-256", elliptic.P256()},
		{"P-384", elliptic.P384()},
		{"P-384/circl", circlp384.P384()},
		{"P-521", elliptic.P521()},
	}

	for _, trial := range trials {
		pp := NewPublicParams(trial.curve)
		b.Run(trial.name, func(b *testing.B) {
			for b.Loop() {
				_, _ = KeyGen(pp)
			}
		})
	}
}

func BenchmarkReEncryptKeyGen(b *testing.B) {
	trials := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P-224", elliptic.P224()},
		{"P-256", elliptic.P256()},
		{"P-384", elliptic.P384()},
		{"P-384/circl", circlp384.P384()},
		{"P-521", elliptic.P521()},
	}

	for _, trial := range trials {
		b.Run(trial.name, func(b *testing.B) {
			pp := NewPublicParams(trial.curve)
			_, aliceSK := KeyGen(pp)
			_, bobSK := KeyGen(pp)
			for b.Loop() {
				_ = ReEncryptionKeyGen(pp, aliceSK, bobSK)
			}
		})
	}
}

func BenchmarkEncrypt(b *testing.B) {
	trials := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P-224", elliptic.P224()},
		{"P-256", elliptic.P256()},
		{"P-384", elliptic.P384()},
		{"P-384/circl", circlp384.P384()},
		{"P-521", elliptic.P521()},
	}

	for _, trial := range trials {
		b.Run(trial.name, func(b *testing.B) {
			pp := NewPublicParams(trial.curve)
			alicePK, _ := KeyGen(pp)
			msg := ecc.NewRandomPoint(trial.curve)
			for b.Loop() {
				_, err := Encrypt(pp, alicePK, msg)
				if err != nil {
					b.Fatalf("Encrypt failed: %v", err)
				}
			}
		})
	}
}

func BenchmarkReEncrypt(b *testing.B) {
	trials := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P-224", elliptic.P224()},
		{"P-256", elliptic.P256()},
		{"P-384", elliptic.P384()},
		{"P-384/circl", circlp384.P384()},
		{"P-521", elliptic.P521()},
	}

	for _, trial := range trials {
		b.Run(trial.name, func(b *testing.B) {
			pp := NewPublicParams(trial.curve)
			alicePK, aliceSK := KeyGen(pp)
			_, bobSK := KeyGen(pp)
			msg := ecc.NewRandomPoint(trial.curve)
			ct, err := Encrypt(pp, alicePK, msg)
			if err != nil {
				b.Fatalf("Encrypt failed: %v", err)
			}

			rkAliceToBob := ReEncryptionKeyGen(pp, aliceSK, bobSK)
			for b.Loop() {
				ReEncrypt(pp, rkAliceToBob, ct)
			}
		})
	}
}

func BenchmarkDecrypt(b *testing.B) {
	trials := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P-224", elliptic.P224()},
		{"P-256", elliptic.P256()},
		{"P-384", elliptic.P384()},
		{"P-384/circl", circlp384.P384()},
		{"P-521", elliptic.P521()},
	}

	for _, trial := range trials {
		b.Run(trial.name, func(b *testing.B) {
			pp := NewPublicParams(trial.curve)
			alicePK, aliceSK := KeyGen(pp)
			msg := ecc.NewRandomPoint(trial.curve)
			ct, err := Encrypt(pp, alicePK, msg)
			if err != nil {
				b.Fatalf("Encrypt failed: %v", err)
			}
			for b.Loop() {
				got := Decrypt(pp, aliceSK, ct)
				b.StopTimer()
				if !got.Equal(msg) {
					b.Fatal("Decrypt produced a value different from original message")
				}
				b.StartTimer()
			}
		})
	}
}
