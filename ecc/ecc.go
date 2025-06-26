package ecc

import (
	"crypto/elliptic"
	"crypto/rand"
	"math/big"

	"github.com/etclab/mu"
)

type Point struct {
	X *big.Int
	Y *big.Int
}

func NewRandomPoint(curve elliptic.Curve) *Point {
	k, err := rand.Int(rand.Reader, curve.Params().N)
	if err != nil {
		mu.BUG("rand.Int failed: %v", err)
	}

	p := new(Point)
	p.X, p.Y = curve.ScalarBaseMult(k.Bytes())
	return p
}

func (p *Point) Equal(other *Point) bool {
	// TODO: does this need to be mod?
	return p.X.Cmp(other.X) == 0 && p.Y.Cmp(other.Y) == 0
}

func (p *Point) Clone() *Point {
	pNew := new(Point)
	pNew.X = new(big.Int)
	pNew.X.Set(p.X)
	pNew.Y = new(big.Int)
	pNew.Y.Set(p.Y)
	return pNew
}
