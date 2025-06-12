package bbs98

// P256, P384, P521, X25519

// P384 offers 102-bit security.
// p-384 is also called secp384r1 or NIST P-384
// import "github.com/cloudflare/circl/ecc/p384"

import (
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"math/big"

	"github.com/etclab/mu"
	"github.com/etclab/ncircl/ecc"
)

type PublicParams struct {
	Curve elliptic.Curve
}

// p384.P384()
func NewPublicParams(curve elliptic.Curve) *PublicParams {
	pp := new(PublicParams)
	pp.Curve = curve
	return pp
}

type PrivateKey struct {
	K *big.Int
}

type PublicKey struct {
	ecc.Point
}

func KeyGen(pp *PublicParams) (*PublicKey, *PrivateKey) {
	var err error
	var k []byte

	curve := pp.Curve

	sk := new(PrivateKey)
	pk := new(PublicKey)

	k, pk.X, pk.Y, err = elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		mu.Panicf("elliptic.GenerateKey failed: %v", err)
	}

	sk.K = new(big.Int)
	sk.K.SetBytes(k)

	return pk, sk
}

type Ciphertext struct {
	C1 *ecc.Point
	C2 *ecc.Point
}

func newCiphertext() *Ciphertext {
	ct := new(Ciphertext)
	ct.C1 = new(ecc.Point)
	ct.C2 = new(ecc.Point)
	return ct
}

func Encrypt(pp *PublicParams, m *ecc.Point, pk *PublicKey) (*Ciphertext, error) {
	curve := pp.Curve
	params := curve.Params()

	if !curve.IsOnCurve(m.X, m.Y) {
		return nil, errors.New("bbs98: message is not a point on the curve")
	}

	r, err := rand.Int(rand.Reader, params.N)
	if err != nil {
		mu.Panicf("rand.Int failed: %v", err)
	}

	ct := newCiphertext()
	x, y := curve.ScalarBaseMult(r.Bytes())
	ct.C1.X, ct.C1.Y = curve.Add(x, y, m.X, m.Y)

	ct.C2.X, ct.C2.Y = curve.ScalarMult(pk.X, pk.Y, r.Bytes())

	return ct, nil
}

type ReEncryptionKey struct {
	RK *big.Int
}

// From a to b
func ReEncryptionKeyGen(pp *PublicParams, a, b *PrivateKey) *ReEncryptionKey {
	curve := pp.Curve
	params := curve.Params()

	aInv := new(big.Int)
	aInv.ModInverse(a.K, params.N)

	rk := new(big.Int)
	rk.Mul(b.K, aInv)

	return &ReEncryptionKey{
		RK: rk,
	}
}

func ReEncrypt(pp *PublicParams, rk *ReEncryptionKey, ct *Ciphertext) {
	curve := pp.Curve
	ct.C2.X, ct.C2.Y = curve.ScalarMult(ct.C2.X, ct.C2.Y, rk.RK.Bytes())
}

func Decrypt(pp *PublicParams, ct *Ciphertext, sk *PrivateKey) *ecc.Point {
	curve := pp.Curve
	params := curve.Params()

	kInv := new(big.Int)
	kInv.ModInverse(sk.K, params.N)

	_, y := curve.ScalarMult(ct.C2.X, ct.C2.Y, kInv.Bytes())

	negY := new(big.Int).Neg(y)
	negY.Mod(negY, params.P)

	m := new(ecc.Point)
	m.X, m.Y = curve.Add(ct.C1.X, ct.C1.Y, ct.C2.X, negY)

	return m
}
