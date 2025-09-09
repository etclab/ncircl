package bbg05

import (
	"errors"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/etclab/ncircl/util/blspairing"
)

var (
	ErrIdExceedsMaxDepth = errors.New("Id exceeds maximum depth")
	ErrIdNotChild        = errors.New("Id is not a valid child of parent Id")
)

type PublicParams struct {
	MaxDepth int
	G        *bls.G1
	G1       *bls.G1
	G2       *bls.G2
	G3       *bls.G2
	Hs       []*bls.G2 // len(Hs) == MaxDepth
}

type MasterKey struct {
	G2toA *bls.G2
}

func Setup(maxDepth int) (*PublicParams, *MasterKey) {
	pp := new(PublicParams)
	pp.MaxDepth = maxDepth

	alpha := blspairing.NewRandomScalar()

	pp.G = bls.G1Generator()

	pp.G1 = new(bls.G1)
	pp.G1.ScalarMult(alpha, pp.G)

	pp.G2 = blspairing.NewRandomG2()

	pp.G3 = blspairing.NewRandomG2()

	pp.Hs = make([]*bls.G2, pp.MaxDepth)
	for i := 0; i < len(pp.Hs); i++ {
		pp.Hs[i] = blspairing.NewRandomG2()
	}

	msk := new(MasterKey)
	msk.G2toA = new(bls.G2)
	msk.G2toA.ScalarMult(alpha, pp.G2)

	return pp, msk
}

type Id struct {
	Is []*bls.Scalar
}

func NewId(pp *PublicParams, components [][]byte) (*Id, error) {
	if len(components) > pp.MaxDepth {
		return nil, ErrIdExceedsMaxDepth
	}
	id := new(Id)
	id.Is = make([]*bls.Scalar, len(components))
	for i := 0; i < len(components); i++ {
		id.Is[i] = blspairing.HashBytesToScalar(components[i])
	}

	return id, nil
}

func NewIdFromStrings(pp *PublicParams, components []string) (*Id, error) {
	if len(components) > pp.MaxDepth {
		return nil, ErrIdExceedsMaxDepth
	}

	byteComponents := make([][]byte, len(components))
	for i := 0; i < len(byteComponents); i++ {
		byteComponents[i] = []byte(components[i])
	}

	return NewId(pp, byteComponents)
}

func (id *Id) Depth() int {
	return len(id.Is)
}

func (id *Id) IsParentOf(childId *Id) bool {
	if id.Depth() != (childId.Depth() - 1) {
		return false
	}

	for i := 0; i < len(id.Is); i++ {
		if id.Is[i].IsEqual(childId.Is[i]) == 0 {
			return false
		}
	}

	return true
}

func (id *Id) IsChildOf(parentId *Id) bool {
	if id.Depth() != (parentId.Depth() + 1) {
		return false
	}

	for i := 0; i < len(parentId.Is); i++ {
		if id.Is[i].IsEqual(parentId.Is[i]) == 0 {
			return false
		}
	}

	return true
}

type PrivateKey struct {
	A0 *bls.G2
	A1 *bls.G1
	Bs []*bls.G2
	Id *Id
}

func KeyGen(pp *PublicParams, msk *MasterKey, id *Id) (*PrivateKey, error) {
	if id.Depth() > pp.MaxDepth {
		return nil, ErrIdExceedsMaxDepth
	}

	r := blspairing.NewRandomScalar()

	agg := blspairing.NewG2Identity()
	var tmp bls.G2
	for i := 0; i < len(id.Is); i++ {
		tmp.ScalarMult(id.Is[i], pp.Hs[i])
		agg.Add(agg, &tmp)
	}
	agg.Add(agg, pp.G3)
	agg.ScalarMult(r, agg)
	A0 := new(bls.G2)
	A0.Add(msk.G2toA, agg)

	A1 := new(bls.G1)
	A1.ScalarMult(r, pp.G)

	Bs := make([]*bls.G2, 0, len(pp.Hs)-len(id.Is))
	for i := len(id.Is); i < len(pp.Hs); i++ {
		b := new(bls.G2)
		b.ScalarMult(r, pp.Hs[i])
		Bs = append(Bs, b)
	}

	return &PrivateKey{
		A0: A0,
		A1: A1,
		Bs: Bs,
		Id: id, /* TODO: clone this? */
	}, nil
}

func KeyDer(pp *PublicParams, parentSk *PrivateKey, childId *Id) (*PrivateKey, error) {
	if childId.Depth() > pp.MaxDepth {
		return nil, ErrIdExceedsMaxDepth
	}
	if !childId.IsChildOf(parentSk.Id) {
		return nil, ErrIdNotChild
	}

	t := blspairing.NewRandomScalar()

	var tmp bls.G2
	agg := blspairing.NewG2Identity()
	for i := 0; i < len(childId.Is); i++ {
		tmp.ScalarMult(childId.Is[i], pp.Hs[i])
		agg.Add(agg, &tmp)
	}
	agg.Add(agg, pp.G3)
	agg.ScalarMult(t, agg)
	k := len(childId.Is) - 1
	tmp.ScalarMult(childId.Is[k], parentSk.Bs[0])
	agg.Add(agg, &tmp)
	agg.Add(agg, parentSk.A0)
	A0 := agg

	A1 := new(bls.G1)
	A1.ScalarMult(t, parentSk.A1)

	Bs := make([]*bls.G2, 0, len(pp.Hs)-len(childId.Is))
	for i := len(childId.Is); i < len(pp.Hs); i++ {
		b := new(bls.G2)
		b.ScalarMult(t, pp.Hs[i])
		b.Add(b, parentSk.Bs[i+1])
		Bs = append(Bs, b)
	}

	return &PrivateKey{
		A0: A0,
		A1: A1,
		Bs: Bs,
		Id: childId, /* TODO: clone this? */
	}, nil
}

type Ciphertext struct {
	A *bls.Gt
	B *bls.G1
	C *bls.G2
}

func Encrypt(pp *PublicParams, id *Id, m *bls.Gt) (*Ciphertext, error) {
	if id.Depth() > pp.MaxDepth {
		return nil, ErrIdExceedsMaxDepth
	}

	s := blspairing.NewRandomScalar()
	A := bls.Pair(pp.G1, pp.G2)
	A.Exp(A, s)
	A.Mul(A, m)

	B := new(bls.G1)
	B.ScalarMult(s, pp.G)

	C := blspairing.NewG2Identity()
	var tmp bls.G2
	for i := 0; i < len(id.Is); i++ {
		tmp.ScalarMult(id.Is[i], pp.Hs[i])
		C.Add(C, &tmp)
	}
	C.Add(C, pp.G3)
	C.ScalarMult(s, C)

	return &Ciphertext{
		A: A,
		B: B,
		C: C,
	}, nil
}

func Decrypt(pp *PublicParams, sk *PrivateKey, ct *Ciphertext) *bls.Gt {
	num := bls.Pair(sk.A1, ct.C)

	denom := bls.Pair(ct.B, sk.A0)
	denom.Inv(denom)

	m := new(bls.Gt)
	m.Mul(num, denom)
	m.Mul(m, ct.A)

	return m
}
