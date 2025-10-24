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
	MaxDepth int // this includes the signature slot
	G        *bls.G2
	G1       *bls.G2
	G2       *bls.G1
	G3       *bls.G1
	Hs       []*bls.G1 // len(Hs) == MaxDepth; the last slot is for signatures
}

func (pp *PublicParams) Clone() *PublicParams {
	hs := make([]*bls.G1, len(pp.Hs))
	for i, h := range pp.Hs {
		hs[i] = blspairing.CloneG1(h)
	}

	return &PublicParams{
		MaxDepth: pp.MaxDepth,
		G:        blspairing.CloneG2(pp.G),
		G1:       blspairing.CloneG2(pp.G1),
		G2:       blspairing.CloneG1(pp.G2),
		G3:       blspairing.CloneG1(pp.G3),
		Hs:       hs,
	}
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

func (p *Pattern) Clone() *Pattern {
	newP := new(Pattern)
	newP.Ps = make([]*bls.Scalar, p.Depth())
	for i := range newP.Ps {
		if p.Ps[i] == nil {
			continue
		}
		newP.Ps[i] = blspairing.CloneScalar(p.Ps[i])
	}
	return newP
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
	for i := range a {
		for j := range b {
			if a[i] == b[j] {
				u = append(u, a[i])
			}
		}
	}
	return u
}

type PrivateKey struct {
	K0      *bls.G1
	K1      *bls.G2
	Bs      []*bls.G1 // len MaxDepth
	Pattern *Pattern
}

func (sk *PrivateKey) Clone() *PrivateKey {
	bs := make([]*bls.G1, len(sk.Bs))
	for i, b := range sk.Bs {
		if b == nil {
			continue
		}
		bs[i] = blspairing.CloneG1(b)
	}

	return &PrivateKey{
		K0:      blspairing.CloneG1(sk.K0),
		K1:      blspairing.CloneG2(sk.K1),
		Bs:      bs,
		Pattern: sk.Pattern.Clone(),
	}
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
	K0 := new(bls.G1)
	K0.Add(msk.G2toAlpha, agg)

	K1 := new(bls.G2)
	K1.ScalarMult(r, pp.G)

	free := pattern.FreeIndices()
	Bs := make([]*bls.G1, pp.MaxDepth)
	for _, i := range free {
		b := new(bls.G1)
		b.ScalarMult(r, pp.Hs[i])
		Bs[i] = b
	}

	return &PrivateKey{
		K0:      K0,
		K1:      K1,
		Bs:      Bs,
		Pattern: pattern.Clone(),
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
	K0 := blspairing.NewG1Identity()
	childFixed := childPattern.FixedIndices()
	for _, i := range childFixed {
		tmp.ScalarMult(childPattern.Ps[i], pp.Hs[i])
		K0.Add(K0, &tmp)
	}
	K0.Add(K0, pp.G3)
	K0.ScalarMult(t, K0)
	K0.Add(K0, parentSk.K0)

	intersection := intersectIndices(childFixed, parentSk.Pattern.FreeIndices())
	for _, i := range intersection {
		tmp.ScalarMult(childPattern.Ps[i], parentSk.Bs[i])
		K0.Add(K0, &tmp)
	}

	K1 := new(bls.G2)
	K1.ScalarMult(t, pp.G)
	K1.Add(K1, parentSk.K1)

	free := childPattern.FreeIndices()
	Bs := make([]*bls.G1, pp.MaxDepth)
	for _, i := range free {
		b := new(bls.G1)
		b.ScalarMult(t, pp.Hs[i])
		b.Add(b, parentSk.Bs[i])
		Bs[i] = b
	}

	return &PrivateKey{
		K0:      K0,
		K1:      K1,
		Bs:      Bs,
		Pattern: childPattern.Clone(),
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
	a := bls.Pair(ct.Z, sk.K1)
	b := bls.Pair(sk.K0, ct.Y)
	b.Inv(b)

	m := new(bls.Gt)
	m.Mul(ct.X, a)
	m.Mul(m, b)

	return m
}

type Signature struct {
	S0 *bls.G1
	S1 *bls.G2
}

// Note that m is a scalar here
func Sign(pp *PublicParams, sk *PrivateKey, m *bls.Scalar) *Signature {
	t := blspairing.NewRandomScalar()

	var tmp bls.G1
	S0 := blspairing.NewG1Identity()
	fixed := sk.Pattern.FixedIndices()
	for _, i := range fixed {
		tmp.ScalarMult(sk.Pattern.Ps[i], pp.Hs[i])
		S0.Add(S0, &tmp)
	}

	tmp.ScalarMult(m, pp.Hs[len(pp.Hs)-1])
	S0.Add(S0, &tmp)
	S0.Add(S0, pp.G3)
	S0.ScalarMult(t, S0)
	S0.Add(S0, sk.K0)
	tmp.ScalarMult(m, sk.Bs[len(sk.Bs)-1])
	S0.Add(S0, &tmp)

	gtoT := new(bls.G2)
	gtoT.ScalarMult(t, pp.G)
	S1 := new(bls.G2)
	S1.Add(gtoT, sk.K1)

	return &Signature{
		S0: S0,
		S1: S1,
	}
}

// Note that m is a scalar here
func Verify(pp *PublicParams, signerPattern *Pattern, sig *Signature, m *bls.Scalar) bool {
	lhs := bls.Pair(sig.S0, pp.G)

	var tmp bls.G1
	a := blspairing.NewG1Identity()
	fixed := signerPattern.FixedIndices()
	for _, i := range fixed {
		tmp.ScalarMult(signerPattern.Ps[i], pp.Hs[i])
		a.Add(a, &tmp)
	}
	tmp.ScalarMult(m, pp.Hs[len(pp.Hs)-1])
	a.Add(a, &tmp)
	a.Add(a, pp.G3)

	rhs := bls.Pair(pp.G2, pp.G1)
	rhs.Mul(rhs, bls.Pair(a, sig.S1))

	return lhs.IsEqual(rhs)
}
