package boolx

import (
	"crypto/rand"

	"github.com/etclab/mu"
)

func Random(n int) []bool {
	out := make([]bool, n)
	var b [1]byte

	for i := 0; i < n; i++ {
		// get a random byte
		_, err := rand.Read(b[:])
		if err != nil {
			mu.Panicf("rand.Read failed: %v", err)
		}

		// extract lowest bit
		bit := b[0] & 1
		out[i] = mu.IntToBool(int(bit))
	}

	return out
}

func All(a []bool) bool {
	for _, x := range a {
		if !x {
			return false
		}
	}
	return true
}

func Any(a []bool) bool {
	for _, x := range a {
		if x {
			return true
		}
	}
	return false
}
