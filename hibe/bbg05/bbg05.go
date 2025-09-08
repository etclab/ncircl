package bbg05

import (
	"errors"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/etclab/ncircl/util/blspairing"
)

var (
	ErrIdExceedsMaxDepth = errors.New("ID exceeds maximum depth")
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

type ID struct {
	Is []*bls.Scalar
}

func NewID(pp *PublicParams, components [][]byte) (*ID, error) {
	if len(components) > pp.MaxDepth {
		return nil, ErrIdExceedsMaxDepth
	}
	id := new(ID)
	id.Is = make([]*bls.Scalar, len(components))
	for i := 0; i < len(components); i++ {
		id.Is[i] = blspairing.HashBytesToScalar(components[i])
	}

	return id, nil
}

type PrivateKey struct {
	A0 *bls.G2
	A1 *bls.G1
	Bs []*bls.G2
	Id *ID
}

func KeyGen(pp *PublicParams, msk *MasterKey, id *ID) (*PrivateKey, error) {
	/* TODO: make sure ID is not beyond max depth */
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

func KeyDer(pp *PublicParams, parentSk *PrivateKey, childId *ID) (*PrivateKey, error) {
	/* TODO: make sure ID is not beyond max depth */
	// TODO: make sure childId is a child of parentSk's id
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

func Encrypt(pp *PublicParams, id *ID, m *bls.Gt) (*Ciphertext, error) {
	/* TODO: make sure ID is not beyond max depth */

	s := blspairing.NewRandomScalar()
	A := bls.Pair(pp.G1, pp.G2)
	A.Exp(A, s)

	B := new(bls.G1)
	B.ScalarMult(s, pp.G)

	C := new(bls.G2)
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
