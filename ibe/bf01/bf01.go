package bf01

import (
	"crypto/sha256"
	"io"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/etclab/mu"
	"github.com/etclab/ncircl/util/blspairing"
	"github.com/etclab/ncircl/util/bytesx"
	"golang.org/x/crypto/hkdf"
)

// H_T: G_2 \leftarrow {0,1)^n
func HT(p *bls.Gt, numBytes int) []byte {
	bytes, err := p.MarshalBinary()
	if err != nil {
		mu.Panicf("Gt.MarshaBinary failed: %v", err)
	}

	kdf := hkdf.New(sha256.New, bytes, nil, nil)

	h := make([]byte, numBytes)
	_, err = io.ReadFull(kdf, h)
	if err != nil {
		mu.Panicf("io.ReadFull failed: %v", err)
	}

	return h
}

type PublicParams struct {
	// master publick key
	MPK *bls.G2
}

type PrivateKeyGenerator struct {
	PP *PublicParams
	// master secret key
	MSK *bls.Scalar
}

func NewPrivateKeyGenerator() (*PrivateKeyGenerator, *PublicParams) {
	pkg := new(PrivateKeyGenerator)
	pp := new(PublicParams)

	pkg.MSK = blspairing.NewRandomScalar()

	pp.MPK = new(bls.G2)
	pp.MPK.ScalarMult(pkg.MSK, bls.G2Generator())

	return pkg, pp
}

type PrivateKey struct {
	SK *bls.G1
}

func (pkg *PrivateKeyGenerator) Extract(id []byte) *PrivateKey {
	sk := new(bls.G1)
	sk.ScalarMult(pkg.MSK, blspairing.HashBytesToG1(id, nil))
	return &PrivateKey{SK: sk}
}

type Ciphertext struct {
	U *bls.G2
	V []byte
}

func Encrypt(pp *PublicParams, id []byte, msg []byte) *Ciphertext {
	r := blspairing.NewRandomScalar()
	u := new(bls.G2)
	u.ScalarMult(r, bls.G2Generator())

	pkId := bls.Pair(blspairing.HashBytesToG1(id, nil), pp.MPK)
	tmp := new(bls.Gt)
	tmp.Exp(pkId, r)
	v := HT(tmp, len(msg))
	bytesx.Xor(v, msg)
	ct := Ciphertext{
		U: u,
		V: v,
	}

	return &ct
}

func Decrypt(pp *PublicParams, sk *PrivateKey, ct *Ciphertext) []byte {
	msg := HT(bls.Pair(sk.SK, ct.U), len(ct.V))
	bytesx.Xor(msg, ct.V)
	return msg
}
