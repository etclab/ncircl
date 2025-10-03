package akn07

import (
	"encoding/binary"
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

type MasterKey struct {
	G2toAlpha *bls.G1 // also called G4
}

func (mk *MasterKey) MarshalBinary() ([]byte, error) {
	return mk.G2toAlpha.Bytes(), nil
}

func (mk *MasterKey) UnmarshalBinary(data []byte) error {
	mk.G2toAlpha = new(bls.G1)
	return mk.G2toAlpha.SetBytes(data)
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

func (pp *PublicParams) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(pp.MaxDepth))

	gBytes := pp.G.Bytes()
	buf = append(buf, gBytes[:]...)

	g1Bytes := pp.G1.Bytes()
	buf = append(buf, g1Bytes[:]...)

	g2Bytes := pp.G2.Bytes()
	buf = append(buf, g2Bytes[:]...)

	g3Bytes := pp.G3.Bytes()
	buf = append(buf, g3Bytes[:]...)

	for i := 0; i < pp.MaxDepth; i++ {
		hBytes := pp.Hs[i].Bytes()
		buf = append(buf, hBytes[:]...)
	}

	return buf, nil
}

func (pp *PublicParams) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return errors.New("invalid public params data: too short")
	}

	pp.MaxDepth = int(binary.BigEndian.Uint32(data[:4]))
	offset := 4

	g2Size := len(bls.G2Generator().Bytes())
	g1Size := len(bls.G1Generator().Bytes())

	if offset+g2Size > len(data) {
		return errors.New("invalid public params data: G truncated")
	}
	pp.G = new(bls.G2)
	if err := pp.G.SetBytes(data[offset : offset+g2Size]); err != nil {
		return err
	}
	offset += g2Size

	if offset+g2Size > len(data) {
		return errors.New("invalid public params data: G1 truncated")
	}
	pp.G1 = new(bls.G2)
	if err := pp.G1.SetBytes(data[offset : offset+g2Size]); err != nil {
		return err
	}
	offset += g2Size

	if offset+g1Size > len(data) {
		return errors.New("invalid public params data: G2 truncated")
	}
	pp.G2 = new(bls.G1)
	if err := pp.G2.SetBytes(data[offset : offset+g1Size]); err != nil {
		return err
	}
	offset += g1Size

	if offset+g1Size > len(data) {
		return errors.New("invalid public params data: G3 truncated")
	}
	pp.G3 = new(bls.G1)
	if err := pp.G3.SetBytes(data[offset : offset+g1Size]); err != nil {
		return err
	}
	offset += g1Size

	pp.Hs = make([]*bls.G1, pp.MaxDepth)
	for i := 0; i < pp.MaxDepth; i++ {
		if offset+g1Size > len(data) {
			return errors.New("invalid public params data: Hs truncated")
		}
		pp.Hs[i] = new(bls.G1)
		if err := pp.Hs[i].SetBytes(data[offset : offset+g1Size]); err != nil {
			return err
		}
		offset += g1Size
	}

	return nil
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

func (p *Pattern) MarshalBinary() ([]byte, error) {
	depth := len(p.Ps)
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(depth))

	for i := 0; i < depth; i++ {
		if p.Ps[i] == nil {
			buf = append(buf, 0)
		} else {
			buf = append(buf, 1)
			scalarBytes, err := p.Ps[i].MarshalBinary()
			if err != nil {
				return nil, err
			}
			buf = append(buf, scalarBytes...)
		}
	}

	return buf, nil
}

func (p *Pattern) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return errors.New("invalid pattern data: too short")
	}

	depth := int(binary.BigEndian.Uint32(data[:4]))
	p.Ps = make([]*bls.Scalar, depth)

	offset := 4
	for i := 0; i < depth; i++ {
		if offset >= len(data) {
			return errors.New("invalid pattern data: unexpected end")
		}

		flag := data[offset]
		offset++

		if flag == 1 {
			if offset+32 > len(data) {
				return errors.New("invalid pattern data: scalar truncated")
			}
			p.Ps[i] = new(bls.Scalar)
			if err := p.Ps[i].UnmarshalBinary(data[offset : offset+32]); err != nil {
				return err
			}
			offset += 32
		}
	}

	return nil
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

func (sk *PrivateKey) MarshalBinary() ([]byte, error) {
	var buf []byte

	k0Bytes := sk.K0.Bytes()
	buf = append(buf, k0Bytes[:]...)

	k1Bytes := sk.K1.Bytes()
	buf = append(buf, k1Bytes[:]...)

	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(sk.Bs)))
	buf = append(buf, lenBuf...)

	for i := 0; i < len(sk.Bs); i++ {
		if sk.Bs[i] == nil {
			buf = append(buf, 0)
		} else {
			buf = append(buf, 1)
			bBytes := sk.Bs[i].Bytes()
			buf = append(buf, bBytes[:]...)
		}
	}

	patternBytes, err := sk.Pattern.MarshalBinary()
	if err != nil {
		return nil, err
	}
	buf = append(buf, patternBytes...)

	return buf, nil
}

func (sk *PrivateKey) UnmarshalBinary(data []byte) error {
	g1Size := len(bls.G1Generator().Bytes())
	g2Size := len(bls.G2Generator().Bytes())

	offset := 0

	if offset+g1Size > len(data) {
		return errors.New("invalid private key data: K0 truncated")
	}
	sk.K0 = new(bls.G1)
	if err := sk.K0.SetBytes(data[offset : offset+g1Size]); err != nil {
		return err
	}
	offset += g1Size

	if offset+g2Size > len(data) {
		return errors.New("invalid private key data: K1 truncated")
	}
	sk.K1 = new(bls.G2)
	if err := sk.K1.SetBytes(data[offset : offset+g2Size]); err != nil {
		return err
	}
	offset += g2Size

	if offset+4 > len(data) {
		return errors.New("invalid private key data: Bs length truncated")
	}
	bsLen := int(binary.BigEndian.Uint32(data[offset : offset+4]))
	offset += 4

	sk.Bs = make([]*bls.G1, bsLen)
	for i := 0; i < bsLen; i++ {
		if offset >= len(data) {
			return errors.New("invalid private key data: Bs flag truncated")
		}

		flag := data[offset]
		offset++

		if flag == 1 {
			if offset+g1Size > len(data) {
				return errors.New("invalid private key data: Bs element truncated")
			}
			sk.Bs[i] = new(bls.G1)
			if err := sk.Bs[i].SetBytes(data[offset : offset+g1Size]); err != nil {
				return err
			}
			offset += g1Size
		}
	}

	sk.Pattern = new(Pattern)
	if err := sk.Pattern.UnmarshalBinary(data[offset:]); err != nil {
		return err
	}

	return nil
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

func (ct *Ciphertext) MarshalBinary() ([]byte, error) {
	xBytes, err := ct.X.MarshalBinary()
	if err != nil {
		return nil, err
	}

	yBytes := ct.Y.Bytes()
	zBytes := ct.Z.Bytes()

	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(len(xBytes)))
	buf = append(buf, xBytes...)
	buf = append(buf, yBytes[:]...)
	buf = append(buf, zBytes[:]...)

	return buf, nil
}

func (ct *Ciphertext) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return errors.New("invalid ciphertext data: too short")
	}

	gtSize := int(binary.BigEndian.Uint32(data[:4]))
	offset := 4

	g2Size := len(bls.G2Generator().Bytes())
	g1Size := len(bls.G1Generator().Bytes())

	expectedSize := 4 + gtSize + g2Size + g1Size
	if len(data) < expectedSize {
		return errors.New("invalid ciphertext data: too short")
	}

	ct.X = new(bls.Gt)
	if err := ct.X.UnmarshalBinary(data[offset : offset+gtSize]); err != nil {
		return err
	}
	offset += gtSize

	ct.Y = new(bls.G2)
	if err := ct.Y.SetBytes(data[offset : offset+g2Size]); err != nil {
		return err
	}
	offset += g2Size

	ct.Z = new(bls.G1)
	if err := ct.Z.SetBytes(data[offset : offset+g1Size]); err != nil {
		return err
	}

	return nil
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
