package bgoy07

import (
	"encoding/hex"
	"errors"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/etclab/ncircl/util/blspairing"
)

var (
	ErrInvalidSignature      = errors.New("bgoy07: invalid signature")
	ErrPublicKeysNotDistinct = errors.New("bgoy07: public keys not distinct")
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
	S *bls.Scalar
	T *bls.Scalar
	U *bls.Scalar
}

type PublicKey struct {
	S *bls.G2
	T *bls.G1
	U *bls.G1
}

func KeyGen(pp *PublicParams) (*PublicKey, *PrivateKey) {
	sk := new(PrivateKey)
	pk := new(PublicKey)

	sk.S = blspairing.NewRandomScalar()
	pk.S = new(bls.G2)
	pk.S.ScalarMult(sk.S, pp.G2)

	sk.T = blspairing.NewRandomScalar()
	pk.T = new(bls.G1)
	pk.T.ScalarMult(sk.T, pp.G1)

	sk.U = blspairing.NewRandomScalar()
	pk.U = new(bls.G1)
	pk.U.ScalarMult(sk.U, pp.G1)

	return pk, sk
}

type Signature struct {
	Q *bls.G1
	X *bls.G2
	Y *bls.G1
	R *bls.G2
}

func NewSignature() *Signature {
	sig := new(Signature)

	sig.Q = blspairing.NewG1Identity()
	sig.X = blspairing.NewG2Identity()
	sig.Y = blspairing.NewG1Identity()
	sig.R = blspairing.NewG2Identity()

	return sig
}

func (s *Signature) Clone() *Signature {
	sig := new(Signature)

	sig.Q = blspairing.CloneG1(s.Q)
	sig.X = blspairing.CloneG2(s.X)
	sig.Y = blspairing.CloneG1(s.Y)
	sig.R = blspairing.CloneG2(s.R)

	return sig
}

func (s *Signature) IsIdentity() bool {
	return s.Q.IsIdentity() && s.X.IsIdentity() && s.Y.IsIdentity() && s.R.IsIdentity()
}

func (s *Signature) Equal(other *Signature) bool {
	return s.Q.IsEqual(other.Q) && s.X.IsEqual(other.X) && s.Y.IsEqual(other.Y) && s.R.IsEqual(other.R)
}

// Assume pks are the pubkeys of all the previous signers.
// muSig is an input, output parameter.
func Sign(pp *PublicParams, sk *PrivateKey, m []byte, muSig *Signature, pks []*PublicKey) error {
	if !muSig.IsIdentity() {
		err := Verify(pp, pks, m, muSig)
		if err != nil {
			return err
		}
	}

	// R' <- R · g^r
	r := blspairing.NewRandomScalar()
	R := new(bls.G2)
	R.ScalarMult(r, pp.G2)
	muSig.R.Add(R, muSig.R)

	// X' <- (R')^{t_i + iu_i} · X
	index := len(pks) + 1 // 1-based indexing
	i := blspairing.NewScalarFromInt(index)
	exp := new(bls.Scalar)
	exp.Mul(i, sk.U)
	exp.Add(exp, sk.T)
	X := new(bls.G2)
	X.ScalarMult(exp, muSig.R)
	muSig.X.Add(X, muSig.X)

	// Y' <- (\prod_{j=1}^{i-1} T_j U_j^j)^r · Y'
	Y := blspairing.NewG1Identity()
	var UtoJ bls.G1
	for j, pk := range pks {
		j = j + 1 // 1-based indexing
		Y.Add(Y, pk.T)
		exp := blspairing.NewScalarFromInt(j)
		UtoJ.ScalarMult(exp, pk.U)
		Y.Add(Y, &UtoJ)
	}
	Y.ScalarMult(r, Y)
	muSig.Y.Add(Y, muSig.Y)

	// Q' <- H(m)^{s_i} · Q
	Q := blspairing.HashBytesToG1(m, nil)
	Q.ScalarMult(sk.S, Q)
	muSig.Q.Add(Q, muSig.Q)

	return nil
}

func Verify(pp *PublicParams, pks []*PublicKey, m []byte, sig *Signature) error {
	// Check that all public keys are distinct
	seen := make(map[string]bool)
	for _, pk := range pks {
		var b []byte
		b = append(b, pk.S.Bytes()...)
		b = append(b, pk.T.Bytes()...)
		b = append(b, pk.U.Bytes()...)
		h := hex.EncodeToString(b)
		if _, exists := seen[h]; !exists {
			seen[h] = true
		} else {
			return ErrPublicKeysNotDistinct
		}
	}

	aggS := blspairing.NewG2Identity()
	aggTU := blspairing.NewG1Identity()

	var UtoJ bls.G1
	for j, pk := range pks {
		j = j + 1 // 1-based indexing
		aggS.Add(aggS, pk.S)

		aggTU.Add(aggTU, pk.T)
		exp := blspairing.NewScalarFromInt(j)
		UtoJ.ScalarMult(exp, pk.U)
		aggTU.Add(aggTU, &UtoJ)
	}
	lhs := bls.Pair(blspairing.HashBytesToG1(m, nil), aggS)
	rhs := bls.Pair(aggTU, sig.R)
	expect := new(bls.Gt)
	expect.Mul(lhs, rhs)

	got := bls.Pair(sig.Q, pp.G2)
	got.Mul(got, bls.Pair(pp.G1, sig.X))
	got.Mul(got, bls.Pair(sig.Y, pp.G2))

	if !got.IsEqual(expect) {
		return ErrInvalidSignature
	}

	return nil
}
