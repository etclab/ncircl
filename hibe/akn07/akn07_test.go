package akn07

import (
	"strings"
	"testing"

	"github.com/etclab/ncircl/util/blspairing"
)

const (
	DefaultDepth = 10
)

func TestDecrypt(t *testing.T) {
	alice := []string{"com", "example", "alice"}

	pp, msk := Setup(DefaultDepth)

	alicePattern, err := NewPatternFromStrings(pp, alice)
	if err != nil {
		t.Fatalf("failed to create pattern: %v", err)
	}

	aliceKey, err := KeyGen(pp, msk, alicePattern)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	m := blspairing.NewRandomGt()

	ct, err := Encrypt(pp, alicePattern, m)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	got := Decrypt(pp, aliceKey, ct)
	if !got.IsEqual(m) {
		t.Fatalf("decryption failed")
	}
}

func TestKeyDer(t *testing.T) {
	parent := []string{"a"}

	pp, msk := Setup(DefaultDepth)

	parentPattern, err := NewPatternFromStrings(pp, parent)
	if err != nil {
		t.Fatalf("failed to create parent pattern: %v", err)
	}

	parentKey, err := KeyGen(pp, msk, parentPattern)
	if err != nil {
		t.Fatalf("KeyGen failed to generate parent key: %v", err)
	}

	strPatterns := [][]string{
		[]string{"a", "b"},
		[]string{"a", "b", "c"},
		[]string{"a", "b", "c", "d"},
		[]string{"a", "b", "c", "d", "e"},
		[]string{"a", "b", "c", "d", "e", "f"},
		[]string{"a", "b", "c", "d", "e", "f", "g"},
		[]string{"a", "b", "c", "d", "e", "f", "g", "h"},
		[]string{"a", "b", "c", "d", "e", "f", "g", "h", "i"},
		[]string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"}, // depth=10
	}

	for _, strPattern := range strPatterns {
		t.Run(strings.Join(strPattern, "."), func(t *testing.T) {
			childPattern, err := NewPatternFromStrings(pp, strPattern)
			if err != nil {
				t.Fatalf("failed to create child pattern %s: %v", strPattern, err)
			}

			childKey, err := KeyDer(pp, parentKey, childPattern)
			if err != nil {
				t.Fatalf("KeyDer failed to generate child key for pattern %s: %v", strPattern, err)
			}

			m := blspairing.NewRandomGt()

			ct, err := Encrypt(pp, childPattern, m)
			if err != nil {
				t.Fatalf("failed to encrypt: %v", err)
			}

			got := Decrypt(pp, childKey, ct)
			if !got.IsEqual(m) {
				t.Fatalf("decryption failed")
			}
		})
	}
}

func TestKeyDer_freeSlots(t *testing.T) {
	parent := []string{"a"}

	pp, msk := Setup(DefaultDepth)

	parentPattern, err := NewPatternFromStrings(pp, parent)
	if err != nil {
		t.Fatalf("failed to create parent pattern: %v", err)
	}

	parentKey, err := KeyGen(pp, msk, parentPattern)
	if err != nil {
		t.Fatalf("KeyGen failed to generate parent key: %v", err)
	}

	strPatterns := [][]string{
		[]string{"a", "", "c"},
		[]string{"a", "", "c", "", "e"},
		[]string{"a", "", "c", "", "e", "", "g"},
		[]string{"a", "", "c", "", "e", "", "g", "", "i"},
	}

	for _, strPattern := range strPatterns {
		t.Run(strings.Join(strPattern, "."), func(t *testing.T) {
			childPattern, err := NewPatternFromStrings(pp, strPattern)
			if err != nil {
				t.Fatalf("failed to create child pattern %s: %v", strPattern, err)
			}

			childKey, err := KeyDer(pp, parentKey, childPattern)
			if err != nil {
				t.Fatalf("KeyDer failed to generate child key for pattern %s: %v", strPattern, err)
			}

			m := blspairing.NewRandomGt()

			ct, err := Encrypt(pp, childPattern, m)
			if err != nil {
				t.Fatalf("failed to encrypt: %v", err)
			}

			got := Decrypt(pp, childKey, ct)
			if !got.IsEqual(m) {
				t.Fatalf("decryption failed")
			}
		})
	}
}

func BenchmarkKeyGen(b *testing.B) {
	pp, msk := Setup(DefaultDepth)

	strPatterns := [][]string{
		[]string{"a"},
		[]string{"a", "b"},
		[]string{"a", "b", "c"},
		[]string{"a", "b", "c", "d"},
		[]string{"a", "b", "c", "d", "e"},
		[]string{"a", "b", "c", "d", "e", "f"},
		[]string{"a", "b", "c", "d", "e", "f", "g"},
		[]string{"a", "b", "c", "d", "e", "f", "g", "h"},
		[]string{"a", "b", "c", "d", "e", "f", "g", "h", "i"},
		[]string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"}, // depth=10
	}

	for _, strPattern := range strPatterns {
		childPattern, err := NewPatternFromStrings(pp, strPattern)
		if err != nil {
			b.Fatalf("failed to create pattern %s: %v", strPattern, err)
		}

		b.Run(strings.Join(strPattern, "."), func(b *testing.B) {
			_, err := KeyGen(pp, msk, childPattern)
			if err != nil {
				b.Fatalf("failed to generate key for pattern %s: %v", strPattern, err)
			}
		})
	}
}

func BenchmarkKeyDer(b *testing.B) {
	parent := []string{"a"}

	pp, msk := Setup(DefaultDepth)

	parentPattern, err := NewPatternFromStrings(pp, parent)
	if err != nil {
		b.Fatalf("failed to create parent pattern %s: %v", parent, err)
	}

	parentKey, err := KeyGen(pp, msk, parentPattern)
	if err != nil {
		b.Fatalf("KeyGen failed to generate parent key: %v", err)
	}

	strPatterns := [][]string{
		[]string{"a", "b"},
		[]string{"a", "b", "c"},
		[]string{"a", "b", "c", "d"},
		[]string{"a", "b", "c", "d", "e"},
		[]string{"a", "b", "c", "d", "e", "f"},
		[]string{"a", "b", "c", "d", "e", "f", "g"},
		[]string{"a", "b", "c", "d", "e", "f", "g", "h"},
		[]string{"a", "b", "c", "d", "e", "f", "g", "h", "i"},
		[]string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"}, // depth=10
	}

	for _, strPattern := range strPatterns {
		childPattern, err := NewPatternFromStrings(pp, strPattern)
		if err != nil {
			b.Fatalf("failed to create pattern %s: %v", strPattern, err)
		}

		b.Run(strings.Join(strPattern, "."), func(b *testing.B) {
			_, err := KeyDer(pp, parentKey, childPattern)
			if err != nil {
				b.Fatalf("failed to generate key for pattern %s: %v", strPattern, err)
			}
		})
	}
}

func BenchmarkEncrypt(b *testing.B) {
	pp, _ := Setup(DefaultDepth)

	strPatterns := [][]string{
		[]string{"a"},
		[]string{"a", "b"},
		[]string{"a", "b", "c"},
		[]string{"a", "b", "c", "d"},
		[]string{"a", "b", "c", "d", "e"},
		[]string{"a", "b", "c", "d", "e", "f"},
		[]string{"a", "b", "c", "d", "e", "f", "g"},
		[]string{"a", "b", "c", "d", "e", "f", "g", "h"},
		[]string{"a", "b", "c", "d", "e", "f", "g", "h", "i"},
		[]string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"}, // depth=10
	}

	m := blspairing.NewRandomGt()

	for _, strPattern := range strPatterns {
		pattern, err := NewPatternFromStrings(pp, strPattern)
		if err != nil {
			b.Fatalf("failed to create pattern %s: %v", strPattern, err)
		}

		b.Run(strings.Join(strPattern, "."), func(b *testing.B) {
			_, err := Encrypt(pp, pattern, m)
			if err != nil {
				b.Fatalf("failed to encrypt to pattern %s: %v", strPattern, err)
			}
		})
	}
}

func BenchmarkDecrypt(b *testing.B) {
	pp, msk := Setup(DefaultDepth)

	strPatterns := [][]string{
		[]string{"a"},
		[]string{"a", "b"},
		[]string{"a", "b", "c"},
		[]string{"a", "b", "c", "d"},
		[]string{"a", "b", "c", "d", "e"},
		[]string{"a", "b", "c", "d", "e", "f"},
		[]string{"a", "b", "c", "d", "e", "f", "g"},
		[]string{"a", "b", "c", "d", "e", "f", "g", "h"},
		[]string{"a", "b", "c", "d", "e", "f", "g", "h", "i"},
		[]string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"}, // depth=10
	}

	m := blspairing.NewRandomGt()

	for _, strPattern := range strPatterns {
		pattern, err := NewPatternFromStrings(pp, strPattern)
		if err != nil {
			b.Fatalf("failed to create pattern %s: %v", strPattern, err)
		}

		ct, err := Encrypt(pp, pattern, m)
		if err != nil {
			b.Fatalf("failed to encrypt to pattern %s: %v", strPattern, err)
		}

		key, err := KeyGen(pp, msk, pattern)
		if err != nil {
			b.Fatalf("KeyGen failed to generate key for pattern %s: %v", strPattern, err)
		}

		b.Run(strings.Join(strPattern, "."), func(b *testing.B) {
			got := Decrypt(pp, key, ct)
			b.StopTimer()
			if !got.IsEqual(m) {
				b.Fatalf("decryption failed for pattern %s", strPattern)
			}
			b.StartTimer()
		})
	}
}
