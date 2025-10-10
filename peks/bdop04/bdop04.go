package bdop04

import (
	"bytes"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/etclab/ncircl/util/blspairing"
)

type PrivateKey struct {
	G1Generator *bls.G1
	Alpha       *bls.Scalar
}

type PublicKey struct {
	G1Generator *bls.G1
	H           *bls.G1
}

func H1(data []byte) *bls.G2 {
	return blspairing.HashBytesToG2(data, nil)
}

func H2(elem *bls.Gt) []byte {
	return blspairing.HashGtToBytes(elem)
}

func KeyGen() (*PublicKey, *PrivateKey) {
	sk := new(PrivateKey)
	sk.G1Generator = bls.G1Generator()
	sk.Alpha = blspairing.NewRandomScalar()

	pk := new(PublicKey)
	pk.G1Generator = blspairing.CloneG1(sk.G1Generator)
	pk.H = new(bls.G1)
	pk.H.ScalarMult(sk.Alpha, pk.G1Generator)

	return pk, sk
}

type SearchableEncryption struct {
	A *bls.G1
	B []byte
}

func PEKS(pk *PublicKey, keyword []byte) *SearchableEncryption {
	r := blspairing.NewRandomScalar()
	hToR := new(bls.G1)
	hToR.ScalarMult(r, pk.H)

	t := bls.Pair(hToR, H1(keyword))

	A := new(bls.G1)
	A.ScalarMult(r, pk.G1Generator)
	B := H2(t)

	return &SearchableEncryption{
		A: A,
		B: B,
	}
}

type Trapdoor struct {
	T *bls.G2
}

func NewTrapdoor(sk *PrivateKey, keyword []byte) *Trapdoor {
	T := new(bls.G2)
	T.ScalarMult(sk.Alpha, H1(keyword))
	return &Trapdoor{
		T: T,
	}
}

func Test(s *SearchableEncryption, t *Trapdoor) bool {
	tmp := bls.Pair(s.A, t.T)
	lhs := H2(tmp)

	return bytes.Equal(lhs, s.B)
}
