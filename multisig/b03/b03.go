package b03

import (
	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/etclab/ncircl/util/blspairing"
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

type PublicKey struct {
	V *bls.G2
}

func KeyGen(pp *PublicParams) (*PublicKey, *PrivateKey) {
	sk := new(PrivateKey)
	pk := new(PublicKey)

	sk.X = blspairing.NewRandomScalar()
	pk.V = new(bls.G2)
	pk.V.ScalarMult(sk.X, pp.G2)

	return pk, sk
}

type Signature struct {
	Sig *bls.G1
}

func NewSignature() *Signature {
	sig := new(Signature)
	sig.Sig = blspairing.NewG1Identity()
	return sig
}

func SingleSign(_ *PublicParams, sk *PrivateKey, msg []byte) *Signature {
	h := blspairing.HashBytesToG1(msg, nil)
	s := NewSignature()
	s.Sig.ScalarMult(sk.X, h)
	return s
}

func Aggregate(_ *PublicParams, sigs []*Signature) *Signature {
	muSig := NewSignature()

	for _, sig := range sigs {
		muSig.Sig.Add(sig.Sig, muSig.Sig)
	}

	return muSig
}

func Sign(pp *PublicParams, sk *PrivateKey, msg []byte, muSig *Signature) {
	sig := SingleSign(pp, sk, msg)
	muSig.Sig.Add(sig.Sig, muSig.Sig)
}

func Verify(pp *PublicParams, pks []*PublicKey, msg []byte, sig *Signature) bool {
	aggPK := blspairing.NewG2Identity()
	for _, pk := range pks {
		aggPK.Add(pk.V, aggPK)
	}

	h := blspairing.HashBytesToG1(msg, nil)
	expect := bls.Pair(h, aggPK)

	got := bls.Pair(sig.Sig, pp.G2)

	return got.IsEqual(expect)
}
