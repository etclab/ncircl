package uint128

// https://www.intel.com/content/www/us/en/docs/cpp-compiler/developer-guide-reference/2021-8/integer-intrinsics-001.html
// https://www.intel.com/content/www/us/en/docs/cpp-compiler/developer-guide-reference/2021-8/shift-intrinsics.html
// https://www.intel.com/content/www/us/en/docs/cpp-compiler/developer-guide-reference/2021-8/macro-function-for-shuffle.html#GUID-C4DC42DC-056A-458C-BCB9-701E96E4D200
/*
[x] _mm_xor_si128
[x] _mm_slli_epi64
[x] _mm_cmpeq_epi8
[x] _mm_set_epi64
[x] _mm_setzero_si128
_mm_shuffle_epi32
_mm_castps_si128
_mm_shuffle_ps
_mm_castsi12i_ps
_mm_move_mask_epi8
*/

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
	x.H = binary.BigEndian.Uint64(b[:8])
	x.L = binary.BigEndian.Uint64(b[8:])
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
	binary.BigEndian.PutUint64(b[:8], x.H)
	binary.BigEndian.PutUint64(b[8:], x.H)
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
	z.L = x.H ^ y.H
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

/*
// _mm_cmpeq_epi8
func CmpeqEpi8(x, y Uint128) Uint128 {
    b := make([]byte, SizeOfUint128)
    bytesX := x.Bytes()
    bytesY := y.Bytes()

    for i := 0; i < SizeOfUint128; i++ {
        if bytesX[i] != bytesY[i] {
            b[0] = 0xff
        }
    }

    var z Uint128
    z.SetBytes(b)
    return z
}

// _mm_shuffle_epi32
func ShuffleEpi32(x Uint128, i int) Uint128 {
}
*/
