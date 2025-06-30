package uint128

// https://www.intel.com/content/www/us/en/docs/cpp-compiler/developer-guide-reference/2021-8/integer-intrinsics-001.html
// https://www.intel.com/content/www/us/en/docs/cpp-compiler/developer-guide-reference/2021-8/shift-intrinsics.html
// https://www.intel.com/content/www/us/en/docs/cpp-compiler/developer-guide-reference/2021-8/macro-function-for-shuffle.html#GUID-C4DC42DC-056A-458C-BCB9-701E96E4D200

import (
	"crypto/rand"
	"encoding/binary"
	"errors"

	"github.com/etclab/mu"
)

const (
	SizeOfUint128 = 16
)

var (
	ErrInvalidSize = errors.New("uin128: Invalid size")
)

// BigEndian
type Uint128 struct {
	H uint64
	L uint64
}

func (x *Uint128) SetBytes(b []byte) error {
	if len(b) != SizeOfUint128 {
		return ErrInvalidSize
	}
	x.L = binary.LittleEndian.Uint64(b[:8])
	x.H = binary.LittleEndian.Uint64(b[8:])
	return nil
}

// _mm_set_epi64
func (x *Uint128) SetEpi64(hi, lo uint64) {
	x.H = hi
	x.L = lo
}

// mm_set_zero_si128
func (x *Uint128) Zero() {
	x.H = 0
	x.L = 0
}

func Random() Uint128 {
	b := make([]byte, SizeOfUint128)
	_, err := rand.Read(b)
	if err != nil {
		mu.Panicf("rand.Read failed: %v", err)
	}

	var x Uint128
	x.SetBytes(b)
	return x
}

// Big-Endian
func (x *Uint128) Bytes() []byte {
	b := make([]byte, SizeOfUint128)
	binary.LittleEndian.PutUint64(b[:8], x.L)
	binary.LittleEndian.PutUint64(b[8:], x.H)
	return b
}

func (x *Uint128) Lsb() int {
	return int(x.L & 1)
}

func Equal(x, y Uint128) bool {
	return x.H == y.H && x.L == y.L
}

// _mm_xor_si128
func Xor(x, y Uint128) Uint128 {
	z := Uint128{}
	z.H = x.H ^ y.H
	z.L = x.L ^ y.L
	return z
}

// _mm_sll_epi64
func SllEpi64(x Uint128, n int) Uint128 {
	if n < 0 || n > 64 {
		mu.Panicf("uint128.SllEpi64: cannot shift by %d bits", n)
	}
	z := Uint128{}
	z.H = x.H << n
	z.L = x.L << n
	return z
}

// Serialize uint128 slice to bytes
func SerializeSlice(values []Uint128) []byte {
	buf := make([]byte, len(values)*SizeOfUint128)
	for i, val := range values {
		copy(buf[i*SizeOfUint128:(i+1)*SizeOfUint128], val.Bytes())
	}
	return buf
}

// Deserialize bytes to uint128 slice
func DeserializeSlice(data []byte) ([]Uint128, error) {
	if len(data)%SizeOfUint128 != 0 {
		return nil, errors.New("invalid data length for uint128 slice")
	}

	count := len(data) / SizeOfUint128
	values := make([]Uint128, count)

	for i := 0; i < count; i++ {
		start := i * SizeOfUint128
		end := start + SizeOfUint128
		err := values[i].SetBytes(data[start:end])
		if err != nil {
			return nil, err
		}
	}
	return values, nil
}
