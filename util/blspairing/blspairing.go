package blspairing

import (
	"crypto/rand"
	"crypto/sha256"
	"io"
	"math/big"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/cloudflare/circl/ecc/bls12381/ff"
	"github.com/etclab/mu"
	"golang.org/x/crypto/hkdf"
)

const (
	Aes256KeySize = 32
)

func NewScalarOne() *bls.Scalar {
	z := new(bls.Scalar)
	z.SetOne()
	return z
}

func NewRandomScalar() *bls.Scalar {
	z := new(bls.Scalar)
	z.Random(rand.Reader)
	return z
}

func CloneScalar(orig *bls.Scalar) *bls.Scalar {
	z := new(bls.Scalar)
	z.Set(orig)
	return z
}

func NewScalarFromInt(i int) *bls.Scalar {
	z := new(bls.Scalar)
	z.SetUint64(uint64(i))
	return z
}

func ScalarToBytes(k *bls.Scalar) []byte {
	buf, err := k.MarshalBinary()
	if err != nil {
		mu.Panicf("Scalar.MarshalBinary failed: %v", err)
	}
	return buf
}

func HashBytesToScalar(msg []byte) *bls.Scalar {
	h := sha256.Sum256(msg)

	z := new(big.Int)
	z.SetBytes(h[:])

	r := new(big.Int)
	r.SetBytes(ff.ScalarOrder())

	z.Rem(z, r)

	k := new(bls.Scalar)
	k.SetBytes(z.Bytes())

	return k
}

func NewG1Identity() *bls.G1 {
	g := new(bls.G1)
	g.SetIdentity()
	return g
}

func NewRandomG1() *bls.G1 {
	g := new(bls.G1)
	input := make([]byte, 128)
	_, err := rand.Read(input)
	if err != nil {
		mu.Fatalf("rand.Read failed to generate %d random bytes", len(input))
	}
	g.Hash(input, nil)
	return g
}

func CloneG1(g *bls.G1) *bls.G1 {
	a := new(bls.G1)
	a.SetBytes(g.Bytes())
	return a
}

func HashBytesToG1(msg, domainSepTag []byte) *bls.G1 {
	g := new(bls.G1)
	g.Hash(msg, domainSepTag)
	return g
}

func NewG2Identity() *bls.G2 {
	g := new(bls.G2)
	g.SetIdentity()
	return g
}

func NewRandomG2() *bls.G2 {
	g := new(bls.G2)
	input := make([]byte, 128)
	_, err := rand.Read(input)
	if err != nil {
		mu.Fatalf("rand.Read failed to generate %d random bytes", len(input))
	}
	g.Hash(input, nil)
	return g
}

func CloneG2(g *bls.G2) *bls.G2 {
	a := new(bls.G2)
	a.SetBytes(g.Bytes())
	return a
}

func HashBytesToG2(msg, domainSepTag []byte) *bls.G2 {
	g := new(bls.G2)
	g.Hash(msg, domainSepTag)
	return g
}

func NewGtIdentity() *bls.Gt {
	g := new(bls.Gt)
	g.SetIdentity()
	return g
}

func GtToBytes(g *bls.Gt) []byte {
	buf, err := g.MarshalBinary()
	if err != nil {
		mu.Panicf("Gt.MarshalBinary failed: %v", err)
	}
	return buf
}

func CloneGt(g *bls.Gt) *bls.Gt {
	a := new(bls.Gt)

	buf, err := g.MarshalBinary()
	if err != nil {
		mu.Panicf("Gt.MarshalBinary failed: %v", err)
	}

	err = a.UnmarshalBinary(buf)
	if err != nil {
		mu.Panicf("Gt.UnmarshalBinary failed: %v", err)
	}

	return a
}

func NewRandomGt() *bls.Gt {
	a := NewRandomScalar()
	b := NewRandomScalar()

	g1 := bls.G1Generator()
	g2 := bls.G2Generator()

	g1.ScalarMult(a, g1)
	g2.ScalarMult(b, g2)

	z := bls.Pair(g1, g2)
	return z
}

func KdfGtToAes256(gt *bls.Gt) []byte {
	bytes, err := gt.MarshalBinary()
	if err != nil {
		mu.Panicf("Gt.MarshalBinary failed: %v", err)
	}

	kdf := hkdf.New(sha256.New, bytes, nil, nil)

	aesKey := make([]byte, Aes256KeySize)
	_, err = io.ReadFull(kdf, aesKey)
	if err != nil {
		mu.Panicf("io.ReadFull failed: %v", err)
	}

	return aesKey
}
