package uint128

import (
	"bytes"
	"fmt"
	"testing"
)

// Test SerializeSlice function
func TestSerializeSlice(t *testing.T) {
	tests := []struct {
		name   string
		input  []Uint128
		expect []byte
	}{
		{
			name:   "empty slice",
			input:  []Uint128{},
			expect: []byte{},
		},
		{
			name: "single value",
			input: []Uint128{
				{H: 0x0123456789ABCDEF, L: 0xFEDCBA9876543210},
			},
			expect: []byte{
				0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,
				0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01,
			},
		},
		{
			name: "multiple values",
			input: []Uint128{
				{H: 0x0000000000000000, L: 0x0000000000000001},
				{H: 0xFFFFFFFFFFFFFFFF, L: 0xFFFFFFFFFFFFFFFF},
				{H: 0x1234567890ABCDEF, L: 0xFEDCBA0987654321},
			},
			expect: []byte{
				// First uint128
				0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				// Second uint128
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				// Third uint128
				0x21, 0x43, 0x65, 0x87, 0x09, 0xBA, 0xDC, 0xFE,
				0xEF, 0xCD, 0xAB, 0x90, 0x78, 0x56, 0x34, 0x12,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SerializeSlice(tt.input)
			if !bytes.Equal(result, tt.expect) {
				t.Errorf("SerializeSlice() = %v, want %v", result, tt.expect)
			}
		})
	}
}

// Test DeserializeSlice function
func TestDeserializeSlice(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		expect    []Uint128
		expectErr bool
	}{
		{
			name:      "empty bytes",
			input:     []byte{},
			expect:    []Uint128{},
			expectErr: false,
		},
		{
			name: "single uint128",
			input: []byte{
				0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,
				0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01,
			},
			expect: []Uint128{
				{H: 0x0123456789ABCDEF, L: 0xFEDCBA9876543210},
			},
			expectErr: false,
		},
		{
			name: "multiple uint128s",
			input: []byte{
				// First uint128
				0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				// Second uint128
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			},
			expect: []Uint128{
				{H: 0x0000000000000000, L: 0x0000000000000001},
				{H: 0xFFFFFFFFFFFFFFFF, L: 0xFFFFFFFFFFFFFFFF},
			},
			expectErr: false,
		},
		{
			name:      "invalid length - not multiple of 16",
			input:     []byte{0x01, 0x02, 0x03, 0x04, 0x05},
			expect:    nil,
			expectErr: true,
		},
		{
			name:      "invalid length - partial uint128",
			input:     make([]byte, 17), // 16 + 1 extra byte
			expect:    nil,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := DeserializeSlice(tt.input)

			if (err != nil) != tt.expectErr {
				t.Errorf("DeserializeSlice() error = %v, expectErr %v", err, tt.expectErr)
				return
			}

			if !tt.expectErr {
				if len(result) != len(tt.expect) {
					t.Errorf("DeserializeSlice() returned %d values, want %d", len(result), len(tt.expect))
					return
				}

				for i, val := range result {
					if val.H != tt.expect[i].H || val.L != tt.expect[i].L {
						t.Errorf("DeserializeSlice()[%d] = {H: %x, L: %x}, want {H: %x, L: %x}",
							i, val.H, val.L, tt.expect[i].H, tt.expect[i].L)
					}
				}
			}
		})
	}
}

// Test round-trip serialization
func TestRoundTripSerialization(t *testing.T) {
	testCases := [][]Uint128{
		{},               // empty slice
		{{H: 0, L: 0}}, // single zero
		{{H: 0xFFFFFFFFFFFFFFFF, L: 0xFFFFFFFFFFFFFFFF}}, // max value
		{
			{H: 0x0123456789ABCDEF, L: 0xFEDCBA9876543210},
			{H: 0x1111111111111111, L: 0x2222222222222222},
			{H: 0xAAAAAAAAAAAAAAAA, L: 0xBBBBBBBBBBBBBBBB},
		}, // multiple values
	}

	for i, original := range testCases {
		t.Run(fmt.Sprintf("round_trip_%d", i), func(t *testing.T) {
			// Serialize
			serialized := SerializeSlice(original)

			// Deserialize
			deserialized, err := DeserializeSlice(serialized)
			if err != nil {
				t.Fatalf("Failed to deserialize: %v", err)
			}

			// Compare
			if len(deserialized) != len(original) {
				t.Fatalf("Length mismatch: got %d, want %d", len(deserialized), len(original))
			}

			for j := range original {
				if deserialized[j].H != original[j].H || deserialized[j].L != original[j].L {
					t.Errorf("Value mismatch at index %d: got {H: %x, L: %x}, want {H: %x, L: %x}",
						j, deserialized[j].H, deserialized[j].L, original[j].H, original[j].L)
				}
			}
		})
	}
}

// Benchmark serialization
func BenchmarkSerializeSlice(b *testing.B) {
	sizes := []int{1, 10, 100, 1000}

	for _, size := range sizes {
		values := make([]Uint128, size)
		for i := range values {
			values[i] = Uint128{H: uint64(i), L: uint64(i * 2)}
		}

		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = SerializeSlice(values)
			}
		})
	}
}

// Benchmark deserialization
func BenchmarkDeserializeSlice(b *testing.B) {
	sizes := []int{1, 10, 100, 1000}

	for _, size := range sizes {
		data := make([]byte, size*SizeOfUint128)

		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _ = DeserializeSlice(data)
			}
		})
	}
}
