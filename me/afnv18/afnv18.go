package afnv18

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
	P  *bls.G1
	P0 *bls.G1
}

type MasterSecretKey struct {
	R *bls.Scalar
	S *bls.Scalar
}

func Setup() (*MasterSecretKey, *PublicParams) {
	msk := new(MasterSecretKey)
	msk.R = blspairing.NewRandomScalar()
	msk.S = blspairing.NewRandomScalar()

	pp := new(PublicParams)
	pp.P = bls.G1Generator()

	pp.P0 = new(bls.G1)
	pp.P0.ScalarMult(msk.R, pp.P)

	return msk, pp
}

type EncryptionKey struct {
	EK *bls.G1
}

func SkGen(_ *PublicParams, msk *MasterSecretKey, id []byte) *EncryptionKey {
	ek := new(EncryptionKey)
	h := blspairing.HashBytesToG1(id, nil)
	ek.EK = new(bls.G1)
	ek.EK.ScalarMult(msk.S, h)
	return ek
}

type DecryptionKey struct {
	DK1 *bls.G2
	DK2 *bls.G2
	DK3 *bls.G2
}

func RkGen(_ *PublicParams, msk *MasterSecretKey, id []byte) *DecryptionKey {
	dk := new(DecryptionKey)

	h := blspairing.HashBytesToG2(id, nil)
	dk.DK1 = new(bls.G2)
	dk.DK1.ScalarMult(msk.R, h)
	dk.DK2 = new(bls.G2)
	dk.DK2.ScalarMult(msk.S, h)
	dk.DK3 = h

	return dk
}

type Ciphertext struct {
	T *bls.G1
	U *bls.G1
	V []byte
}

func Encrypt(pp *PublicParams, ek *EncryptionKey, rcvId []byte, msg []byte) *Ciphertext {
	ct := new(Ciphertext)

	t := blspairing.NewRandomScalar()
	ct.T = new(bls.G1)
	ct.T.ScalarMult(t, pp.P)

	u := blspairing.NewRandomScalar()
	ct.U = new(bls.G1)
	ct.U.ScalarMult(u, pp.P)

	h := blspairing.HashBytesToG2(rcvId, nil)
	p0toU := new(bls.G1)
	p0toU.ScalarMult(u, pp.P0)
	kR := bls.Pair(p0toU, h)

	tmp := new(bls.G1)
	tmp.Add(ct.T, ek.EK)
	kS := bls.Pair(tmp, h)

	n := len(msg)
	ct.V = make([]byte, n)
	copy(ct.V, msg)
	bytesx.Xor(ct.V, HT(kR, n))
	bytesx.Xor(ct.V, HT(kS, n))

	return ct
}

func Decrypt(_ *PublicParams, dk *DecryptionKey, sndId []byte, ct *Ciphertext) []byte {
	kR := bls.Pair(ct.U, dk.DK1)

	h := blspairing.HashBytesToG1(sndId, nil)
	a := bls.Pair(h, dk.DK2)
	b := bls.Pair(ct.T, dk.DK3)
	kS := new(bls.Gt)
	kS.Mul(a, b)

	n := len(ct.V)
	msg := make([]byte, n)
	copy(msg, ct.V)
	bytesx.Xor(msg, HT(kR, n))
	bytesx.Xor(msg, HT(kS, n))

	return msg
}
