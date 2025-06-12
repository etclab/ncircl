package bytesx

import (
	"crypto/rand"

	"github.com/etclab/mu"
)

func Random(numBytes int) []byte {
	buf := make([]byte, numBytes)
	_, err := rand.Read(buf)
	if err != nil {
		mu.Fatalf("rand.Read failed: %v", err)
	}
	return buf
}

func Xor(a, b []byte) {
	n := min(len(a), len(b))
	for i := 0; i < n; i++ {
		a[i] ^= b[i]
	}
}
