package akn07

import (
	"errors"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/etclab/ncircl/util/blspairing"
)

var (
	ErrPatternExceedsMaxDepth = errors.New("Pattern is longer than the max depth")
	ErrPatternInvalidDepth    = errors.New("Pattern must be of max depth length")
	ErrPatternDoesNotMatch    = errors.New("Pattern does not match parent")
)

// This is also called the master public key (mpk)
type PublicParams struct {
	MaxDepth int
	G        *bls.G2
	G1       *bls.G2
	G2       *bls.G1
	G3       *bls.G1
	Hs       []*bls.G1 // len(Hs) == MaxDepth
}

type MasterKey struct {
	G2toAlpha *bls.G1 // also called G4
}

func Setup(maxDepth int) (*PublicParams, *MasterKey) {
	pp := new(PublicParams)
	pp.MaxDepth = maxDepth

	alpha := blspairing.NewRandomScalar()

	pp.G = bls.G2Generator()

	pp.G1 = new(bls.G2)
	pp.G1.ScalarMult(alpha, pp.G)

	pp.G2 = blspairing.NewRandomG1()

	pp.G3 = blspairing.NewRandomG1()

	pp.Hs = make([]*bls.G1, pp.MaxDepth)
	for i := 0; i < len(pp.Hs); i++ {
		pp.Hs[i] = blspairing.NewRandomG1()
	}

	msk := new(MasterKey)
	msk.G2toAlpha = new(bls.G1)
	msk.G2toAlpha.ScalarMult(alpha, pp.G2)

	return pp, msk
}

type Pattern struct {
	Ps []*bls.Scalar // len MaxDepth
}

func NewPattern(pp *PublicParams, components [][]byte) (*Pattern, error) {
	if len(components) != pp.MaxDepth {
		return nil, ErrPatternInvalidDepth
	}
	pattern := new(Pattern)
	pattern.Ps = make([]*bls.Scalar, len(components))
	for i := 0; i < len(components); i++ {
		if components[i] == nil {
			pattern.Ps[i] = nil
		} else {
			pattern.Ps[i] = blspairing.HashBytesToScalar(components[i])
		}
	}

	return pattern, nil
}

func NewPatternFromStrings(pp *PublicParams, components []string) (*Pattern, error) {
	if len(components) > pp.MaxDepth {
		return nil, ErrPatternExceedsMaxDepth
	}

	byteComponents := make([][]byte, pp.MaxDepth)
	for i := 0; i < len(components); i++ {
		if components[i] != "" {
			byteComponents[i] = []byte(components[i])
		}
	}

	return NewPattern(pp, byteComponents)
}

func (p *Pattern) Depth() int {
	return len(p.Ps)
}

func (p *Pattern) Matches(other *Pattern) bool {
	for i := 0; i < len(p.Ps); i++ {
		if p.Ps[i] == nil {
			continue
		}

		if other.Ps[i] == nil {
			return false
		}

		if p.Ps[i].IsEqual(other.Ps[i]) == 0 {
			return false
		}
	}

	return true
}

func (p *Pattern) FixedIndices() []int {
	var fixed []int
	for i, p := range p.Ps {
		if p != nil {
			fixed = append(fixed, i)
		}
	}
	return fixed
}

func (p *Pattern) FreeIndices() []int {
	var free []int
	for i, p := range p.Ps {
		if p == nil {
			free = append(free, i)
		}
	}
	return free
}

func intersectIndices(a, b []int) []int {
	// FIXME: simple, but inefficient method
	var u []int
	for _, i := range a {
		for _, j := range b {
			if a[i] == b[j] {
				u = append(u, a[i])
			}
		}
	}
	return u
}

type PrivateKey struct {
	A1      *bls.G1
	A2      *bls.G2
	Bs      []*bls.G1 // len MaxDepth
	Pattern *Pattern
}

func KeyGen(pp *PublicParams, msk *MasterKey, pattern *Pattern) (*PrivateKey, error) {
	if pattern.Depth() != pp.MaxDepth {
		return nil, ErrPatternInvalidDepth
	}

	r := blspairing.NewRandomScalar()

	var tmp bls.G1
	agg := blspairing.NewG1Identity()
	fixed := pattern.FixedIndices()
	for _, i := range fixed {
		tmp.ScalarMult(pattern.Ps[i], pp.Hs[i])
		agg.Add(agg, &tmp)
	}
	agg.Add(agg, pp.G3)
	agg.ScalarMult(r, agg)
	A1 := new(bls.G1)
	A1.Add(msk.G2toAlpha, agg)

	A2 := new(bls.G2)
	A2.ScalarMult(r, pp.G)

	free := pattern.FreeIndices()
	Bs := make([]*bls.G1, pp.MaxDepth)
	for _, i := range free {
		b := new(bls.G1)
		b.ScalarMult(r, pp.Hs[i])
		Bs[i] = b
	}

	return &PrivateKey{
		A1:      A1,
		A2:      A2,
		Bs:      Bs,
		Pattern: pattern, /* TODO: clone this? */
	}, nil
}

func KeyDer(pp *PublicParams, parentSk *PrivateKey, childPattern *Pattern) (*PrivateKey, error) {
	if childPattern.Depth() != pp.MaxDepth {
		return nil, ErrPatternInvalidDepth
	}

	if !parentSk.Pattern.Matches(childPattern) {
		return nil, ErrPatternDoesNotMatch
	}

	t := blspairing.NewRandomScalar()

	var tmp bls.G1
	A1 := blspairing.NewG1Identity()
	childFixed := childPattern.FixedIndices()
	for _, i := range childFixed {
		tmp.ScalarMult(childPattern.Ps[i], pp.Hs[i])
		A1.Add(A1, &tmp)
	}
	A1.Add(A1, pp.G3)
	A1.ScalarMult(t, A1)
	A1.Add(A1, parentSk.A1)

	intersection := intersectIndices(childFixed, parentSk.Pattern.FreeIndices())
	for _, i := range intersection {
		tmp.ScalarMult(childPattern.Ps[i], parentSk.Bs[i])
		A1.Add(A1, &tmp)
	}

	A2 := new(bls.G2)
	A2.ScalarMult(t, pp.G)
	A2.Add(A2, parentSk.A2)

	free := childPattern.FreeIndices()
	Bs := make([]*bls.G1, pp.MaxDepth)
	for _, i := range free {
		b := new(bls.G1)
		b.ScalarMult(t, pp.Hs[i])
		b.Add(b, parentSk.Bs[i])
		Bs[i] = b
	}

	return &PrivateKey{
		A1:      A1,
		A2:      A2,
		Bs:      Bs,
		Pattern: childPattern, /* TODO: clone this? */
	}, nil
}

type Ciphertext struct {
	X *bls.Gt
	Y *bls.G2
	Z *bls.G1
}

func Encrypt(pp *PublicParams, pattern *Pattern, m *bls.Gt) (*Ciphertext, error) {
	if pattern.Depth() != pp.MaxDepth {
		return nil, ErrPatternInvalidDepth
	}

	s := blspairing.NewRandomScalar()

	X := bls.Pair(pp.G2, pp.G1)
	X.Exp(X, s)
	X.Mul(X, m)

	Y := new(bls.G2)
	Y.ScalarMult(s, pp.G)

	Z := blspairing.NewG1Identity()
	var tmp bls.G1
	fixed := pattern.FixedIndices()
	for _, i := range fixed {
		tmp.ScalarMult(pattern.Ps[i], pp.Hs[i])
		Z.Add(Z, &tmp)
	}
	Z.Add(Z, pp.G3)
	Z.ScalarMult(s, Z)

	return &Ciphertext{
		X: X,
		Y: Y,
		Z: Z,
	}, nil
}

func Decrypt(pp *PublicParams, sk *PrivateKey, ct *Ciphertext) *bls.Gt {
	a := bls.Pair(ct.Z, sk.A2)
	b := bls.Pair(sk.A1, ct.Y)
	b.Inv(b)

	m := new(bls.Gt)
	m.Mul(ct.X, a)
	m.Mul(m, b)

	return m
}
