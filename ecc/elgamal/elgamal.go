package elgamal

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

func NewPublicParams(curve elliptic.Curve) *PublicParams {
	pp := new(PublicParams)
	pp.Curve = curve
	return pp
}

type PrivateKey struct {
	K []byte
}

type PublicKey struct {
	ecc.Point
}

func KeyGen(pp *PublicParams) (*PublicKey, *PrivateKey) {
	var err error

	curve := pp.Curve

	sk := new(PrivateKey)
	pk := new(PublicKey)

	sk.K, pk.X, pk.Y, err = elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		mu.Panicf("elliptic.GenerateKey failed: %v", err)
	}

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

func Encrypt(pp *PublicParams, pk *PublicKey, msg *ecc.Point) (*Ciphertext, error) {
	var err error
	var r []byte

	curve := pp.Curve

	if !curve.IsOnCurve(msg.X, msg.Y) {
		return nil, errors.New("elgamal: message is not a point on the curve")
	}

	ct := newCiphertext()

	r, ct.C1.X, ct.C1.Y, err = elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		mu.Panicf("elliptic.GenerateKey failed: %v", err)
	}

	x, y := curve.ScalarMult(pk.X, pk.Y, r)
	ct.C2.X, ct.C2.Y = curve.Add(x, y, msg.X, msg.Y)

	return ct, nil
}

func Decrypt(pp *PublicParams, sk *PrivateKey, ct *Ciphertext) *ecc.Point {
	curve := pp.Curve
	params := curve.Params()

	x, y := curve.ScalarMult(ct.C1.X, ct.C1.Y, sk.K)

	negY := new(big.Int).Neg(y)
	negY.Mod(negY, params.P)

	mx, my := curve.Add(ct.C2.X, ct.C2.Y, x, negY)

	return &ecc.Point{X: mx, Y: my}
}
