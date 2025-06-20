package ch07

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/etclab/mu"
	"github.com/etclab/ncircl/util/blspairing"
)

var (
	ErrInvalidSignature  = errors.New("ch07: invalid signature")
	ErrInvalidCiphertext = errors.New("ch07: invalid ciphertext")
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

func (sk *PrivateKey) PublicKey(pp *PublicParams) *PublicKey {
	pk := new(PublicKey)
	pk.Y = new(bls.G1)
	pk.Y.ScalarMult(sk.X, pp.G1)
	return pk
}

type PublicKey struct {
	Y *bls.G1
}

func KeyGen(pp *PublicParams) (*PublicKey, *PrivateKey) {
	sk := new(PrivateKey)
	sk.X = blspairing.NewRandomScalar()

	pk := new(PublicKey)
	pk.Y = new(bls.G1)
	pk.Y.ScalarMult(sk.X, pp.G1)

	return pk, sk
}

type ReEncryptionKey struct {
	RK *bls.Scalar
}

func ReEncryptionKeyGen(_ *PublicParams, aliceSK *PrivateKey, bobSK *PrivateKey) *ReEncryptionKey {
	rk := new(bls.Scalar)
	rk.Inv(aliceSK.X)

	rk.Mul(bobSK.X, rk) /* mod q? */

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

func (ct *Ciphertext) Clone() *Ciphertext {
	ctNew := new(Ciphertext)

	ctNew.A = make([]byte, len(ct.A))
	copy(ctNew.A, ct.A)

	ctNew.B = blspairing.CloneG1(ct.B)
	ctNew.C = blspairing.CloneGt(ct.C)
	ctNew.D = blspairing.CloneG2(ct.D)
	ctNew.E = blspairing.CloneG2(ct.E)

	ctNew.S = make([]byte, len(ct.S))
	copy(ctNew.S, ct.S)

	return ctNew
}

func (ct *Ciphertext) MessageToSign() []byte {
	m := make([]byte, 0, 1024)
	m = append(m, blspairing.GtToBytes(ct.C)...)
	m = append(m, ct.D.Bytes()...)
	m = append(m, ct.E.Bytes()...)
	return m
}

func (ct *Ciphertext) Check(pp *PublicParams, pk *PublicKey) error {
	m := ct.MessageToSign()
	if !ed25519.Verify(ct.A, m, ct.S) {
		return ErrInvalidSignature
	}

	lhs := bls.Pair(ct.B, blspairing.HashBytesToG2(ct.A, nil))
	rhs := bls.Pair(pk.Y, ct.D)
	if !lhs.IsEqual(rhs) {
		return ErrInvalidCiphertext
	}

	lhs = bls.Pair(ct.B, pp.G2)
	rhs = bls.Pair(pk.Y, ct.E)
	if !lhs.IsEqual(rhs) {
		return ErrInvalidCiphertext
	}

	return nil
}

func Encrypt(pp *PublicParams, pk *PublicKey, msg *bls.Gt) *Ciphertext {
	svk, ssk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		mu.Panicf("ed25519.GenerateKey failed: %v", err)

	}
	r := blspairing.NewRandomScalar()

	B := new(bls.G1)
	B.ScalarMult(r, pk.Y)

	C := bls.Pair(pp.G1, blspairing.HashBytesToG2(svk, nil))
	C.Exp(C, r)
	C.Mul(C, msg)

	D := blspairing.HashBytesToG2(svk, nil)
	D.ScalarMult(r, D)

	E := new(bls.G2)
	E.ScalarMult(r, pp.G2)

	ct := &Ciphertext{
		A: svk,
		B: B,
		C: C,
		D: D,
		E: E,
	}

	m := ct.MessageToSign()
	ct.S = ed25519.Sign(ssk, m)

	return ct
}

func ReEncrypt(pp *PublicParams, rk *ReEncryptionKey, bobPK *PublicKey, ct *Ciphertext) (*Ciphertext, error) {
	ctNew := ct.Clone()
	ctNew.B.ScalarMult(rk.RK, ct.B)
	if err := ctNew.Check(pp, bobPK); err != nil {
		return nil, err
	}
	return ctNew, nil
}

func Decrypt(pp *PublicParams, sk *PrivateKey, ct *Ciphertext) (*bls.Gt, error) {
	if err := ct.Check(pp, sk.PublicKey(pp)); err != nil {
		return nil, err
	}

	z := bls.Pair(ct.B, blspairing.HashBytesToG2(ct.A, nil))
	exp := new(bls.Scalar)
	exp.Inv(sk.X)
	z.Exp(z, exp)
	z.Inv(z)

	msg := new(bls.Gt)
	msg.Mul(ct.C, z)

	return msg, nil
}
