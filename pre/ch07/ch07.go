package ch07

import (
	"crypto/ed25519"
	//"crypto/rand"
	bls "github.com/cloudflare/circl/ecc/bls12381"
	//"github.com/etclab/mu"
	"github.com/etclab/ncircl/util/blspairing"
)

type PublicParams struct {
	G1 *bls.G1
	G2 *bls.G2
}

func NewPublicParams() *PublicParams {
	pp := new(PublicParams)

	pp.G1 = bls.G1Generator()
	pp.G2 = bls.G2Generator()

	return pp
}

type PrivateKey struct {
	X *bls.Scalar
}

type PublicKey struct {
	G1ToX *bls.G1
}

func KeyGen(pp *PublicParams) (*PublicKey, *PrivateKey) {
	sk := new(PrivateKey)
	sk.X = blspairing.NewRandomScalar()

	pk := new(PublicKey)
	pk.G1ToX = new(bls.G1)
	pk.G1ToX.ScalarMult(sk.X, pp.G1)

	return pk, sk
}

type ReEncryptionKey struct {
	RK *bls.Scalar
}

func ReEncryptionKeyGen(_ *PublicParams, aliceSK *PrivateKey, bobSK *PrivateKey) *ReEncryptionKey {
	rk := new(bls.Scalar)
	rk.Inv(aliceSK.X)

	rk.Mul(bobSK.X, rk)

	return &ReEncryptionKey{
		RK: rk,
	}
}

type Ciphertext struct {
	A ed25519.PublicKey
	B *bls.G1
	C *bls.Gt
	D *bls.G2
	E *bls.G2
	S []byte
}

/*
func Encrypt(pp *PublicParams, m *bls.Gt, pk *PublicKey) *Ciphertext {
	svk, ssk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		mu.Panicf("ed25519.GenerateKey failed: %v", err)

	}
	r := blspairing.NewRandomScalar()

	B := new(bls.G1)
	B.ScalarMult(r, pk.G1ToX)

	C := bls.Pair(pp.G1, blspairing.HashBytesToG2(svk))
	C.ScalarMult(r, C)
	C.Add(C, m)

	D := blspairing.HashBytesToG2(svk)
	D.ScalarMult(r, D)

	E := new(bls.G2),
		E.ScalarMult(r, pp.G2.Generator)

	msgToSign := make([]byte, 0, 128)
	data, err := C.MarshalBinary()
	if err != nil {
		mu.Panicf("Gt.MarshalBinary() failed: %v", err)
	}
	msgToSign := append(msgToSign, data)
	data = D.Bytes()
	msgToSign := append(msgToSign, data)
	data = E.Bytes()
	msgToSign := append(msgToSign, data)

	sig = ed25519.Sign(ssk, msgToSign)

	return &Ciphertext{
		A: svk,
		B: B,
		C: C,
		D: D,
		E: E,
		S: sig,
	}
}

// TODO: ReEncrypt

// TODO:
func Decrypt(pp *PublicParams, ct1 *Ciphertext1, sk *PrivateKey) *bls.Gt {
}
*/
