package bf01

import (
	"bytes"
	"testing"
)

func TestDecrypt(t *testing.T) {
	// Setup
	pkg, pp := NewPrivateKeyGenerator()

	// Generate secret keys
	bobSK := pkg.Extract([]byte("bob"))

	// 32-byte message
	msg := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345")

	// Alice encrypts the message to Bob
	ct := Encrypt(pp, []byte("bob"), msg)

	// Bob decrypts the message
	got := Decrypt(pp, bobSK, ct)

	if !bytes.Equal(msg, got) {
		t.Fatalf("expected decrypted message to be %x, but got %x", msg, got)
	}
}

func BenchmarkExtract(b *testing.B) {
	pkg, _ := NewPrivateKeyGenerator()
	id := []byte("test@example.com")
	for b.Loop() {
		_ = pkg.Extract(id)
	}
}

func BenchmarkEncrypt(b *testing.B) {
	_, pp := NewPrivateKeyGenerator()
	id := []byte("test@example.com")
	msg := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345")
	for b.Loop() {
		_ = Encrypt(pp, id, msg)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	pkg, pp := NewPrivateKeyGenerator()
	id := []byte("test@example.com")
	idSK := pkg.Extract(id)
	msg := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345")
	ct := Encrypt(pp, id, msg)
	for b.Loop() {
		got := Decrypt(pp, idSK, ct)
		b.StopTimer()
		if !bytes.Equal(msg, got) {
			b.Fatalf("expected decrypted message to be %x, but got %x", msg, got)
		}
		b.StartTimer()
	}
}
