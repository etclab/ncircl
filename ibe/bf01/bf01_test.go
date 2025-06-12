package bf01

import (
	"bytes"
	"testing"
)

func TestDecrypt(t *testing.T) {
	// Setup
	pkg, pp := NewPrivateKeyGenerator(32)

	// Generate secret keys
	bobSK := pkg.Extract([]byte("bob"))

	// 32-byte message
	msg := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345")

	// Alice encrypts the message to Bob
	c, err := Encrypt(pp, []byte("bob"), msg)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Bob decrypts the message
	got := Decrypt(pp, bobSK, c)

	if !bytes.Equal(msg, got) {
		t.Fatalf("expected decrypted message to be %x, but got %x", msg, got)
	}
}

func BenchmarkExtract(b *testing.B) {
	pkg, _ := NewPrivateKeyGenerator(32)
	id := []byte("test@example.com")
	for i := 0; i < b.N; i++ {
		_ = pkg.Extract(id)
	}
}

func BenchmarkEncrypt(b *testing.B) {
	_, pp := NewPrivateKeyGenerator(32)
	id := []byte("test@example.com")
	msg := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345")
	for b.Loop() {
		_, err := Encrypt(pp, id, msg)
		if err != nil {
			b.Fatalf("Encrypt failed: %v", err)
		}
	}
}

func BenchmarkDecrypt(b *testing.B) {
	pkg, pp := NewPrivateKeyGenerator(32)
	id := []byte("test@example.com")
	idSK := pkg.Extract(id)
	msg := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345")
	ct, err := Encrypt(pp, id, msg)
	if err != nil {
		b.Fatalf("Encrypt failed: %v", err)
	}
	for b.Loop() {
		got := Decrypt(pp, idSK, ct)
		b.StopTimer()
		if !bytes.Equal(msg, got) {
			b.Fatalf("expected decrypted message to be %x, but got %x", msg, got)
		}
		b.StartTimer()
	}
}
