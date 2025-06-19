package lv08

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/etclab/mu"
	"github.com/etclab/ncircl/util/blspairing"
)

var (
	ErrInvalidSignature   = errors.New("lv08: invalid signature")
	ErrInvalidCiphertext1 = errors.New("lv08: invalid first-level ciphertext")
	ErrInvalidCiphertext2 = errors.New("lv08: invalid second-level ciphertext")
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
	pk.Y1 = new(bls.G1)
	pk.Y1.ScalarMult(sk.X, pp.G1)
	pk.Y2 = new(bls.G2)
	pk.Y2.ScalarMult(sk.X, pp.G2)
	return pk
}

type PublicKey struct {
	Y1 *bls.G1
	Y2 *bls.G2 // orig
}

func KeyGen(pp *PublicParams) (*PublicKey, *PrivateKey) {
	sk := new(PrivateKey)
	sk.X = blspairing.NewRandomScalar()

	pk := new(PublicKey)
	pk.Y1 = new(bls.G1)
	pk.Y1.ScalarMult(sk.X, pp.G1)
	pk.Y2 = new(bls.G2)
	pk.Y2.ScalarMult(sk.X, pp.G2)

	return pk, sk
}

type ReEncryptionKey struct {
	DelegatorPK *PublicKey
	RK          *bls.G1 // XXX: smh; was G2
}

func ReEncryptionKeyGen(pp *PublicParams, aliceSK *PrivateKey, bobPK *PublicKey) *ReEncryptionKey {
	x := new(bls.Scalar)
	x.Inv(aliceSK.X)

	// XXX: shm; was G2
	rk := new(bls.G1)
	rk.ScalarMult(x, bobPK.Y1)

	return &ReEncryptionKey{
		DelegatorPK: aliceSK.PublicKey(pp),
		RK:          rk,
	}
}

type Ciphertext1 struct {
	C1            ed25519.PublicKey
	C2Prime       *bls.G2
	C2DoublePrime *bls.G1
	C2TriplePrime *bls.G2
	C3            *bls.Gt
	C4            *bls.G1
	S             []byte
}

func (ct *Ciphertext1) MessageToSign() []byte {
	m := make([]byte, 0, 1024)
	m = append(m, blspairing.GtToBytes(ct.C3)...)
	m = append(m, ct.C4.Bytes()...)
	return m
}

func (ct *Ciphertext1) Check(pp *PublicParams, pk *PublicKey) error {
	m := ct.MessageToSign()
	if !ed25519.Verify(ct.C1, m, ct.S) {
		return ErrInvalidSignature
	}

	lhs := bls.Pair(ct.C2DoublePrime, ct.C2Prime)
	rhs := bls.Pair(pp.G1, pk.Y2)
	if !lhs.IsEqual(rhs) {
		return ErrInvalidCiphertext1
	}

	svkScalar := new(bls.Scalar)
	svkScalar.SetBytes(ct.C1)
	g := new(bls.G1)
	g.ScalarMult(svkScalar, pp.G1)
	g.Add(g, pp.G1)
	lhs = bls.Pair(g, ct.C2TriplePrime)
	rhs = bls.Pair(ct.C4, ct.C2Prime)
	if !lhs.IsEqual(rhs) {
		return ErrInvalidCiphertext1
	}

	return nil
}

func Encrypt1(pp *PublicParams, pk *PublicKey, msg *bls.Gt) *Ciphertext1 {
	svk, ssk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		mu.Panicf("ed25519.GenerateKey failed: %v", err)
	}

	r := blspairing.NewRandomScalar()
	t := blspairing.NewRandomScalar()

	C2Prime := new(bls.G2)
	C2Prime.ScalarMult(t, pk.Y2)

	tInv := new(bls.Scalar)
	tInv.Inv(t)
	C2DoublePrime := new(bls.G1)
	C2DoublePrime.ScalarMult(tInv, pp.G1)

	rt := new(bls.Scalar)
	rt.Mul(r, t)
	C2TriplePrime := new(bls.G2)
	C2TriplePrime.ScalarMult(rt, pk.Y2)

	C3 := new(bls.Gt)
	C3 = bls.Pair(pp.G1, pp.G2)
	C3.Exp(C3, r)
	C3.Mul(C3, msg)

	svkScalar := new(bls.Scalar)
	svkScalar.SetBytes(svk)
	C4 := new(bls.G1)
	C4.ScalarMult(svkScalar, pp.G1)
	C4.Add(C4, pp.G1)
	C4.ScalarMult(r, C4)

	ct := &Ciphertext1{
		C1:            svk,
		C2Prime:       C2Prime,
		C2DoublePrime: C2DoublePrime,
		C2TriplePrime: C2TriplePrime,
		C3:            C3,
		C4:            C4,
	}

	m := ct.MessageToSign()
	ct.S = ed25519.Sign(ssk, m)

	return ct
}

func Decrypt1(pp *PublicParams, sk *PrivateKey, ct *Ciphertext1) (*bls.Gt, error) {
	if err := ct.Check(pp, sk.PublicKey(pp)); err != nil {
		return nil, err
	}

	z := bls.Pair(ct.C2DoublePrime, ct.C2TriplePrime)
	exp := new(bls.Scalar)
	exp.Inv(sk.X)
	z.Exp(z, exp)
	z.Inv(z)

	msg := new(bls.Gt)
	msg.Mul(ct.C3, z)

	return msg, nil
}

type Ciphertext2 struct {
	C1 ed25519.PublicKey
	C2 *bls.G2
	C3 *bls.Gt
	C4 *bls.G1
	S  []byte
}

func (ct *Ciphertext2) MessageToSign() []byte {
	m := make([]byte, 0, 1024)
	m = append(m, blspairing.GtToBytes(ct.C3)...)
	m = append(m, ct.C4.Bytes()...)
	return m
}

func (ct *Ciphertext2) Check(pp *PublicParams, pk *PublicKey) error {
	m := ct.MessageToSign()
	if !ed25519.Verify(ct.C1, m, ct.S) {
		return ErrInvalidSignature
	}

	svkScalar := new(bls.Scalar)
	svkScalar.SetBytes(ct.C1)
	g := new(bls.G1)
	g.ScalarMult(svkScalar, pp.G1)
	g.Add(g, pp.G1)
	lhs := bls.Pair(g, ct.C2)
	rhs := bls.Pair(ct.C4, pk.Y2)
	if !lhs.IsEqual(rhs) {
		return ErrInvalidCiphertext2
	}

	return nil
}

func Encrypt2(pp *PublicParams, pk *PublicKey, msg *bls.Gt) *Ciphertext2 {
	svk, ssk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		mu.Panicf("ed25519.GenerateKey failed: %v", err)
	}

	r := blspairing.NewRandomScalar()

	C2 := new(bls.G2)
	C2.ScalarMult(r, pk.Y2)

	C3 := new(bls.Gt)
	C3 = bls.Pair(pp.G1, pp.G2)
	C3.Exp(C3, r)
	C3.Mul(C3, msg)

	svkScalar := new(bls.Scalar)
	svkScalar.SetBytes(svk)
	C4 := new(bls.G1)
	C4.ScalarMult(svkScalar, pp.G1)
	C4.Add(C4, pp.G1)
	C4.ScalarMult(r, C4)

	ct := &Ciphertext2{
		C1: svk,
		C2: C2,
		C3: C3,
		C4: C4,
	}

	m := ct.MessageToSign()
	ct.S = ed25519.Sign(ssk, m)

	return ct
}

func Decrypt2(pp *PublicParams, sk *PrivateKey, ct *Ciphertext2) (*bls.Gt, error) {
	if err := ct.Check(pp, sk.PublicKey(pp)); err != nil {
		return nil, err
	}

	z := bls.Pair(pp.G1, ct.C2)
	exp := new(bls.Scalar)
	exp.Inv(sk.X)
	z.Exp(z, exp)
	z.Inv(z)

	msg := new(bls.Gt)
	msg.Mul(ct.C3, z)

	return msg, nil
}

func ReEncrypt(pp *PublicParams, rk *ReEncryptionKey, ct2 *Ciphertext2) (*Ciphertext1, error) {
	if err := ct2.Check(pp, rk.DelegatorPK); err != nil {
		return nil, err
	}

	t := blspairing.NewRandomScalar()
	C2Prime := new(bls.G2)
	C2Prime.ScalarMult(t, rk.DelegatorPK.Y2)

	tInv := new(bls.Scalar)
	tInv.Inv(t)
	C2DoublePrime := new(bls.G1)
	/* This is what requires the public key to have two elements instead of one */
	C2DoublePrime.ScalarMult(tInv, rk.RK)

	C2TriplePrime := new(bls.G2)
	C2TriplePrime.ScalarMult(t, ct2.C2)

	C1 := make(ed25519.PublicKey, len(ct2.C1))
	copy(C1, ct2.C1)

	S := make([]byte, len(ct2.S))
	copy(S, ct2.S)

	ct1 := &Ciphertext1{
		C1:            C1,
		C2Prime:       C2Prime,
		C2DoublePrime: C2DoublePrime,
		C2TriplePrime: C2TriplePrime,
		C3:            blspairing.DupGt(ct2.C3),
		C4:            blspairing.DupG1(ct2.C4),
		S:             S,
	}

	return ct1, nil
}
