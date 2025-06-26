package bgls03

import (
	"errors"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/etclab/ncircl/util/blspairing"
)

var (
	ErrInvalidSignature    = errors.New("bgls03: invalid signature")
	ErrMessagesNotDistinct = errors.New("bgls03: not all messages are distinct")
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

func (sig *Signature) Clone() *Signature {
	newSig := new(Signature)
	newSig.Sig = blspairing.CloneG1(sig.Sig)
	return newSig
}

func (sig *Signature) Equal(other *Signature) bool {
    return sig.Sig.IsEqual(other.Sig)
}

func Aggregate(_ *PublicParams, sigs []*Signature) *Signature {
	aggSig := NewSignature()

	for _, sig := range sigs {
		aggSig.Sig.Add(sig.Sig, aggSig.Sig)
	}

	return aggSig
}

func Sign(_ *PublicParams, sk *PrivateKey, msg []byte, aggSig *Signature) *Signature {
	h := blspairing.HashBytesToG1(msg, nil)
	s := NewSignature()
	s.Sig.ScalarMult(sk.X, h)

	if aggSig == nil {
		return s
	}

	aggSig.Sig.Add(s.Sig, aggSig.Sig)

	return aggSig
}

func Verify(pp *PublicParams, pks []*PublicKey, msgs [][]byte, aggSig *Signature) error {
	// Ensure messages are all distinct, and reject otherwise
	seen := make(map[bls.G1]bool)
	expect := blspairing.NewGtIdentity()
	for i := 0; i < len(pks); i++ {
		pk := pks[i]
		m := msgs[i]
		h := blspairing.HashBytesToG1(m, nil)
		if _, exists := seen[*h]; !exists {
			seen[*h] = true
		} else {
			return ErrMessagesNotDistinct
		}
		expect.Mul(bls.Pair(h, pk.V), expect)
	}

	got := bls.Pair(aggSig.Sig, pp.G2)

	if !got.IsEqual(expect) {
		return ErrInvalidSignature
	}

	return nil
}
