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

func TestPatternSerialization(t *testing.T) {
	pp, _ := Setup(DefaultDepth)

	tests := []struct {
		name    string
		pattern []string
	}{
		{"fully fixed", []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"}},
		{"some free", []string{"a", "", "c", "", "e"}},
		{"first free", []string{"", "b", "c"}},
		{"last free", []string{"a", "b", ""}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original, err := NewPatternFromStrings(pp, tt.pattern)
			if err != nil {
				t.Fatalf("failed to create pattern: %v", err)
			}

			data, err := original.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary failed: %v", err)
			}

			deserialized := new(Pattern)
			if err := deserialized.UnmarshalBinary(data); err != nil {
				t.Fatalf("UnmarshalBinary failed: %v", err)
			}

			if deserialized.Depth() != original.Depth() {
				t.Fatalf("depth mismatch: got %d, want %d", deserialized.Depth(), original.Depth())
			}

			for i := 0; i < original.Depth(); i++ {
				if (original.Ps[i] == nil) != (deserialized.Ps[i] == nil) {
					t.Fatalf("nil mismatch at index %d", i)
				}
				if original.Ps[i] != nil && deserialized.Ps[i] != nil {
					if original.Ps[i].IsEqual(deserialized.Ps[i]) == 0 {
						t.Fatalf("scalar mismatch at index %d", i)
					}
				}
			}
		})
	}
}

func TestPublicParamsSerialization(t *testing.T) {
	original, _ := Setup(DefaultDepth)

	data, err := original.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	deserialized := new(PublicParams)
	if err := deserialized.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary failed: %v", err)
	}

	if deserialized.MaxDepth != original.MaxDepth {
		t.Fatalf("MaxDepth mismatch: got %d, want %d", deserialized.MaxDepth, original.MaxDepth)
	}

	if !deserialized.G.IsEqual(original.G) {
		t.Fatalf("G mismatch")
	}

	if !deserialized.G1.IsEqual(original.G1) {
		t.Fatalf("G1 mismatch")
	}

	if !deserialized.G2.IsEqual(original.G2) {
		t.Fatalf("G2 mismatch")
	}

	if !deserialized.G3.IsEqual(original.G3) {
		t.Fatalf("G3 mismatch")
	}

	if len(deserialized.Hs) != len(original.Hs) {
		t.Fatalf("Hs length mismatch: got %d, want %d", len(deserialized.Hs), len(original.Hs))
	}

	for i := range original.Hs {
		if !deserialized.Hs[i].IsEqual(original.Hs[i]) {
			t.Fatalf("Hs[%d] mismatch", i)
		}
	}
}

func TestMasterKeySerialization(t *testing.T) {
	_, original := Setup(DefaultDepth)

	data, err := original.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	deserialized := new(MasterKey)
	if err := deserialized.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary failed: %v", err)
	}

	if !deserialized.G2toAlpha.IsEqual(original.G2toAlpha) {
		t.Fatalf("G2toAlpha mismatch")
	}
}

func TestPrivateKeySerialization(t *testing.T) {
	pp, msk := Setup(DefaultDepth)

	tests := []struct {
		name    string
		pattern []string
	}{
		{"fully fixed", []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"}},
		{"some free", []string{"a", "", "c", "", "e"}},
		{"first free", []string{"", "b", "c"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pattern, err := NewPatternFromStrings(pp, tt.pattern)
			if err != nil {
				t.Fatalf("failed to create pattern: %v", err)
			}

			original, err := KeyGen(pp, msk, pattern)
			if err != nil {
				t.Fatalf("KeyGen failed: %v", err)
			}

			data, err := original.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary failed: %v", err)
			}

			deserialized := new(PrivateKey)
			if err := deserialized.UnmarshalBinary(data); err != nil {
				t.Fatalf("UnmarshalBinary failed: %v", err)
			}

			if !deserialized.K0.IsEqual(original.K0) {
				t.Fatalf("K0 mismatch")
			}

			if !deserialized.K1.IsEqual(original.K1) {
				t.Fatalf("K1 mismatch")
			}

			if len(deserialized.Bs) != len(original.Bs) {
				t.Fatalf("Bs length mismatch: got %d, want %d", len(deserialized.Bs), len(original.Bs))
			}

			for i := range original.Bs {
				if (original.Bs[i] == nil) != (deserialized.Bs[i] == nil) {
					t.Fatalf("Bs[%d] nil mismatch", i)
				}
				if original.Bs[i] != nil && deserialized.Bs[i] != nil {
					if !deserialized.Bs[i].IsEqual(original.Bs[i]) {
						t.Fatalf("Bs[%d] mismatch", i)
					}
				}
			}

			if deserialized.Pattern.Depth() != original.Pattern.Depth() {
				t.Fatalf("Pattern depth mismatch: got %d, want %d", deserialized.Pattern.Depth(), original.Pattern.Depth())
			}

			for i := 0; i < original.Pattern.Depth(); i++ {
				if (original.Pattern.Ps[i] == nil) != (deserialized.Pattern.Ps[i] == nil) {
					t.Fatalf("Pattern.Ps[%d] nil mismatch", i)
				}
				if original.Pattern.Ps[i] != nil && deserialized.Pattern.Ps[i] != nil {
					if original.Pattern.Ps[i].IsEqual(deserialized.Pattern.Ps[i]) == 0 {
						t.Fatalf("Pattern.Ps[%d] mismatch", i)
					}
				}
			}

			// Verify the deserialized key still works for decryption
			m := blspairing.NewRandomGt()
			ct, err := Encrypt(pp, pattern, m)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}

			got := Decrypt(pp, deserialized, ct)
			if !got.IsEqual(m) {
				t.Fatalf("decryption with deserialized key failed")
			}
		})
	}
}
