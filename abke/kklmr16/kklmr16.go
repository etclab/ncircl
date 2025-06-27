package kklmr16

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/etclab/mu"
	"github.com/etclab/ncircl/util/blspairing"
	"github.com/etclab/ncircl/util/uint128"
)

type PublicParams struct {
	NumAttrs int // m
}

func NewPublicParams(numAttrs int) *PublicParams {
	if numAttrs <= 0 {
		mu.Fatalf("numAttrs must be > 0")
	}

	pp := new(PublicParams)
	pp.NumAttrs = numAttrs
	return pp
}

type ElhKeyPair struct {
	SK *bls.Scalar
	PK *bls.G2
}

func NewElhKeyPair() *ElhKeyPair {
	kp := new(ElhKeyPair)
	kp.SK = blspairing.NewRandomScalar()

	g2 := bls.G2Generator()
	kp.PK = new(bls.G2)
	kp.PK.ScalarMult(kp.SK, g2)

	return kp
}

func (kp *ElhKeyPair) Sign(msg *bls.G1) *bls.G1 {
	return ElhSign(kp.SK, msg)
}

func ElhSign(sk *bls.Scalar, msg *bls.G1) *bls.G1 {
	sig := new(bls.G1)
	sig.ScalarMult(sk, msg)
	return sig
}

func ElhVerify(pk *bls.G2, sig, msg *bls.G1) bool {
	g2 := bls.G2Generator()
	gt1 := bls.Pair(sig, g2)
	gt2 := bls.Pair(msg, pk)
	return gt1.IsEqual(gt2)
}

type MasterKey struct {
	GKeyPair  *ElhKeyPair
	HKeyPair  *ElhKeyPair
	UKeyPair  *ElhKeyPair
	JKeyPairs []*ElhKeyPair
}

func NewMasterKey(pp *PublicParams) *MasterKey {
	m := new(MasterKey)
	m.GKeyPair = NewElhKeyPair()
	m.HKeyPair = NewElhKeyPair()
	m.UKeyPair = NewElhKeyPair()

	m.JKeyPairs = make([]*ElhKeyPair, pp.NumAttrs)
	for i := 0; i < pp.NumAttrs; i++ {
		m.JKeyPairs[i] = NewElhKeyPair()
	}

	return m
}

type MSK struct {
	G  *bls.Scalar
	H  *bls.Scalar
	U  *bls.Scalar
	Js []*bls.Scalar
}

func (m *MasterKey) MSK() *MSK {
	msk := new(MSK)

	msk.G = blspairing.CloneScalar(m.GKeyPair.SK)
	msk.H = blspairing.CloneScalar(m.HKeyPair.SK)
	msk.U = blspairing.CloneScalar(m.UKeyPair.SK)

	msk.Js = make([]*bls.Scalar, len(m.JKeyPairs))
	for i, j := range m.JKeyPairs {
		msk.Js[i] = blspairing.CloneScalar(j.SK)
	}

	return msk
}

// also called MVK in the paper
type MPK struct {
	G  *bls.G2
	H  *bls.G2
	U  *bls.G2
	Js []*bls.G2
}

func (m *MasterKey) MPK() *MPK {
	mpk := new(MPK)

	mpk.G = blspairing.CloneG2(m.GKeyPair.PK)
	mpk.H = blspairing.CloneG2(m.HKeyPair.PK)
	mpk.U = blspairing.CloneG2(m.UKeyPair.PK)

	mpk.Js = make([]*bls.G2, len(m.JKeyPairs))
	for i, j := range m.JKeyPairs {
		mpk.Js[i] = blspairing.CloneG2(j.PK)
	}

	return mpk
}

func (mpk *MPK) MarshalBinary() ([]byte, error) {

	g2Size := bls.G2SizeCompressed

	totalSize := 4 + 3*g2Size + len(mpk.Js)*g2Size

	buf := make([]byte, totalSize)

	binary.BigEndian.PutUint32(buf[0:4], uint32(len(mpk.Js)))
	offset := 4

	copy(buf[offset:offset+g2Size], mpk.G.BytesCompressed())
	offset += g2Size

	copy(buf[offset:offset+g2Size], mpk.H.BytesCompressed())
	offset += g2Size

	copy(buf[offset:offset+g2Size], mpk.U.BytesCompressed())
	offset += g2Size

	for _, j := range mpk.Js {
		copy(buf[offset:offset+g2Size], j.BytesCompressed())
		offset += g2Size
	}

	return buf, nil

}

func (mpk *MPK) UnmarshalBinary(data []byte) error {
	g2Size := bls.G2SizeCompressed

	if len(data) < 4+3*g2Size {
		return fmt.Errorf("data too short: %d bytes", len(data))
	}

	numJs := binary.BigEndian.Uint32(data[0:4])
	offset := 4

	expectedSize := 4 + 3*g2Size + int(numJs)*g2Size
	if len(data) < expectedSize {
		return fmt.Errorf("data too short for expected size: %d bytes", expectedSize)
	}

	mpk.G = new(bls.G2)
	if err := mpk.G.SetBytes(data[offset : offset+g2Size]); err != nil {
		return fmt.Errorf("failed to unmarshal G: %w", err)
	}
	offset += g2Size

	mpk.H = new(bls.G2)
	if err := mpk.H.SetBytes(data[offset : offset+g2Size]); err != nil {
		return fmt.Errorf("failed to unmarshal H: %w", err)
	}
	offset += g2Size

	mpk.U = new(bls.G2)
	if err := mpk.U.SetBytes(data[offset : offset+g2Size]); err != nil {
		return fmt.Errorf("failed to unmarshal U: %w", err)
	}
	offset += g2Size

	mpk.Js = make([]*bls.G2, numJs)
	for i := uint32(0); i < numJs; i++ {
		if offset+g2Size > len(data) {
			return fmt.Errorf("data too short for J[%d]", i)
		}
		mpk.Js[i] = new(bls.G2)
		if err := mpk.Js[i].SetBytes(data[offset : offset+g2Size]); err != nil {
			return fmt.Errorf("failed to unmarshal J[%d]: %w", i, err)
		}
		offset += g2Size
	}
	return nil
}

func (mpk *MPK) IsEqual(other *MPK) bool {
	if mpk == nil || other == nil {
		return mpk == other
	}

	if !mpk.G.IsEqual(other.G) || !mpk.H.IsEqual(other.H) || !mpk.U.IsEqual(other.U) {
		return false
	}

	if len(mpk.Js) != len(other.Js) {
		return false
	}

	for i := range mpk.Js {
		if !mpk.Js[i].IsEqual(other.Js[i]) {
			return false
		}
	}

	return true
}

type PublicKey struct {
	G     *bls.G1
	H     *bls.G1
	U     *bls.G1
	GSig  *bls.G1
	HSig  *bls.G1
	USig  *bls.G1
	Es    []*bls.G1
	ESigs []*bls.G1
}

func NewPublicKey(pp *PublicParams) *PublicKey {
	pk := new(PublicKey)
	pk.Es = make([]*bls.G1, pp.NumAttrs)
	pk.ESigs = make([]*bls.G1, pp.NumAttrs)
	return pk
}

func (pk *PublicKey) String() string {
	sb := new(strings.Builder)
	fmt.Fprintf(sb, "G: %v,\nGSig: %v,\n", pk.G, pk.GSig)
	fmt.Fprintf(sb, "H: %v,\nHSig: %v,\n", pk.H, pk.HSig)
	fmt.Fprintf(sb, "U: %v,\nUSig: %v,\n", pk.U, pk.USig)
	for i, e := range pk.Es {
		fmt.Fprintf(sb, "E[%d]: %v,\nESig[%d]: %v,\n", i, e, i, pk.ESigs[i])
	}
	return sb.String()
}

// Vrfy, ase_homosig_vrfy
func (pk *PublicKey) Verify(pp *PublicParams, mpk *MPK) bool {
	// g ∈ G\{1}
	if !pk.G.IsOnG1() || pk.G.IsIdentity() {
		return false
	}
	// h ∈ G\{1}
	if !pk.H.IsOnG1() || pk.H.IsIdentity() {
		return false
	}
	// u ∈ G\{1}
	if !pk.U.IsOnG1() || pk.U.IsIdentity() {
		return false
	}

	if !ElhVerify(mpk.G, pk.GSig, pk.G) {
		return false
	}
	if !ElhVerify(mpk.H, pk.HSig, pk.H) {
		return false
	}
	if !ElhVerify(mpk.U, pk.USig, pk.U) {
		return false
	}

	tmp := new(bls.G1)
	for i := 0; i < pp.NumAttrs; i++ {
		tmp.Add(pk.U, pk.Es[i])
		if !ElhVerify(mpk.Js[i], pk.ESigs[i], tmp) {
			return false
		}
	}

	return true
}

type PrivateKey struct {
	Rs    []*bls.Scalar
	Attrs []bool
}

func NewPrivateKey(pp *PublicParams, attrs []bool) *PrivateKey {
	if len(attrs) != pp.NumAttrs {
		mu.BUG("bad attrs length: pp.NumAttrs=%d, len(attrs)=%d", pp.NumAttrs, len(attrs))
	}
	sk := new(PrivateKey)
	sk.Rs = make([]*bls.Scalar, pp.NumAttrs)
	sk.Attrs = make([]bool, pp.NumAttrs)
	copy(sk.Attrs, attrs)
	return sk
}

func (sk *PrivateKey) String() string {
	sb := new(strings.Builder)
	for i, r := range sk.Rs {
		fmt.Fprintf(sb, "[%d] = %v\n", i, r)
	}
	return sb.String()
}

// Unlink, ase_homosig_unlink
func Unlink(pp *PublicParams, pk *PublicKey, sk *PrivateKey) (*PublicKey, *PrivateKey) {
	newPk := NewPublicKey(pp)
	newSk := NewPrivateKey(pp, sk.Attrs)

	r := blspairing.NewRandomScalar()

	newPk.G = new(bls.G1)
	newPk.G.ScalarMult(r, pk.G)
	newPk.GSig = new(bls.G1)
	newPk.GSig.ScalarMult(r, pk.GSig)

	newPk.H = new(bls.G1)
	newPk.H.ScalarMult(r, pk.H)
	newPk.HSig = new(bls.G1)
	newPk.HSig.ScalarMult(r, pk.HSig)

	newPk.U = new(bls.G1)
	newPk.U.ScalarMult(r, pk.U)
	newPk.USig = new(bls.G1)
	newPk.USig.ScalarMult(r, pk.USig)

	for i := 0; i < len(pk.Es); i++ {
		newPk.Es[i] = new(bls.G1)
		newPk.Es[i].ScalarMult(r, pk.Es[i])
		newPk.ESigs[i] = new(bls.G1)
		newPk.ESigs[i].ScalarMult(r, pk.ESigs[i])
		newSk.Rs[i] = blspairing.CloneScalar(sk.Rs[i])
	}

	return newPk, newSk
}

type CertificateAuthority struct {
	PP *PublicParams
	MK *MasterKey
}

// Setup
func NewCertificateAuthority(pp *PublicParams) *CertificateAuthority {
	ca := new(CertificateAuthority)
	ca.PP = pp
	ca.MK = NewMasterKey(pp)
	return ca
}

func (ca *CertificateAuthority) MPK() *MPK {
	return ca.MK.MPK()
}

// GenCert,  ase_homosig_gen()
func (ca *CertificateAuthority) GenCert(attrs []bool) (*PublicKey, *PrivateKey) {
	pk := NewPublicKey(ca.PP)
	sk := NewPrivateKey(ca.PP, attrs)

	pk.G = blspairing.NewRandomG1()
	pk.H = blspairing.NewRandomG1()
	pk.U = blspairing.NewRandomG1()

	pk.GSig = ca.MK.GKeyPair.Sign(pk.G)
	pk.HSig = ca.MK.HKeyPair.Sign(pk.H)
	pk.USig = ca.MK.UKeyPair.Sign(pk.U)

	tmp := new(bls.G1)
	for i := 0; i < ca.PP.NumAttrs; i++ {
		sk.Rs[i] = blspairing.NewRandomScalar()
		pk.Es[i] = new(bls.G1)
		if attrs[i] {
			pk.Es[i].ScalarMult(sk.Rs[i], pk.H)
		} else {
			pk.Es[i].ScalarMult(sk.Rs[i], pk.G)
		}

		tmp.Add(pk.Es[i], pk.U)
		pk.ESigs[i] = ca.MK.JKeyPairs[i].Sign(tmp)
	}

	return pk, sk
}

type Ciphertext struct {
	G   *bls.G1
	H   *bls.G1
	C2s []*bls.G1
}

func (ct *Ciphertext) String() string {
	sb := new(strings.Builder)

	fmt.Fprintf(sb, "{g: %v,\nh: %v,\nc2s: [\n", ct.G, ct.H)
	for i, c2 := range ct.C2s {
		fmt.Fprintf(sb, "\t[%d] %v,\n", i, c2)
	}
	fmt.Fprintf(sb, "}")

	return sb.String()
}

// Enc, ase_homosig_enc
// Note that len(plaintext) = 2 * numAttrs
// the caller usually passes nil for attrs
func Encrypt(pp *PublicParams, pk *PublicKey, attrs []bool, plaintext []*bls.G1) *Ciphertext {
	ct := new(Ciphertext)

	s := blspairing.NewRandomScalar()
	ct.G = new(bls.G1)
	ct.G.ScalarMult(s, pk.G)

	t := blspairing.NewRandomScalar()
	ct.H = new(bls.G1)
	ct.H.ScalarMult(t, pk.H)

	idx := 0
	tmp := new(bls.G1)
	ct.C2s = make([]*bls.G1, 2*pp.NumAttrs)
	for i := 0; i < pp.NumAttrs; i++ {
		if attrs == nil || !attrs[i] {
			idx = 2 * i
			tmp.ScalarMult(s, pk.Es[i])
			ct.C2s[idx] = new(bls.G1)
			ct.C2s[idx].Add(plaintext[idx], tmp)
		}
		if attrs == nil || attrs[i] {
			idx = 2*i + 1
			tmp.ScalarMult(t, pk.Es[i])
			ct.C2s[idx] = new(bls.G1)
			ct.C2s[idx].Add(plaintext[idx], tmp)
		}
	}

	return ct
}

// Dec, ase_homosig_dec
func Decrypt(pp *PublicParams, sk *PrivateKey, ct *Ciphertext) []*bls.G1 {
	tmp := new(bls.G1)

	pt := make([]*bls.G1, pp.NumAttrs)
	for i := 0; i < pp.NumAttrs; i++ {
		pt[i] = new(bls.G1)
		if sk.Attrs[i] {
			tmp.ScalarMult(sk.Rs[i], ct.H)
			tmp.Neg()
			pt[i].Add(ct.C2s[2*i+1], tmp)
		} else {
			tmp.ScalarMult(sk.Rs[i], ct.G)
			tmp.Neg()
			pt[i].Add(ct.C2s[2*i], tmp)
		}
	}

	return pt
}

// util.c::hash
func Hash(g *bls.G1, idx int, bit bool) uint128.Uint128 {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint32(idx))
	binary.Write(buf, binary.BigEndian, uint8(mu.BoolToInt(bit)))
	buf.Write(g.Bytes())

	h := sha256.Sum256(buf.Bytes())

	var block uint128.Uint128
	block.SetBytes(h[:16])
	return block
}
