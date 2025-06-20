package kklmr16

import (
	"fmt"
	"strings"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/etclab/mu"
	"github.com/etclab/ncircl/util/blspairing"
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

type PublicKey struct {
	g     *bls.G1
	h     *bls.G1
	u     *bls.G1
	gsig  *bls.G1
	hsig  *bls.G1
	usig  *bls.G1
	es    []*bls.G1
	esigs []*bls.G1
}

func NewPublicKey(pp *PublicParams) *PublicKey {
	pk := new(PublicKey)
	pk.es = make([]*bls.G1, pp.NumAttrs)
	pk.esigs = make([]*bls.G1, pp.NumAttrs)
	return pk
}

func (pk *PublicKey) String() string {
	sb := new(strings.Builder)
	fmt.Fprintf(sb, "g: %v,\ngsig: %v,\n", pk.g, pk.gsig)
	fmt.Fprintf(sb, "h: %v,\nhsig: %v,\n", pk.h, pk.hsig)
	fmt.Fprintf(sb, "u: %v,\nusig: %v,\n", pk.u, pk.usig)
	for i, e := range pk.es {
		fmt.Fprintf(sb, "e[%d]: %v,\nesig[%d]: %v,\n", i, e, i, pk.esigs[i])
	}
	return sb.String()
}

// Vrfy, ase_homosig_vrfy
func (pk *PublicKey) Verify(pp *PublicParams, mpk *MPK) bool {
	// g ∈ G\{1}
	if !pk.g.IsOnG1() || pk.g.IsIdentity() {
		return false
	}
	// h ∈ G\{1}
	if !pk.h.IsOnG1() || pk.h.IsIdentity() {
		return false
	}
	// u ∈ G\{1}
	if !pk.u.IsOnG1() || pk.u.IsIdentity() {
		return false
	}

	if !ElhVerify(mpk.G, pk.gsig, pk.g) {
		return false
	}
	if !ElhVerify(mpk.H, pk.hsig, pk.h) {
		return false
	}
	if !ElhVerify(mpk.U, pk.usig, pk.u) {
		return false
	}

	tmp := new(bls.G1)
	for i := 0; i < pp.NumAttrs; i++ {
		tmp.Add(pk.u, pk.es[i])
		if !ElhVerify(mpk.Js[i], pk.esigs[i], tmp) {
			return false
		}
	}

	return true
}

type PrivateKey struct {
	Rs []*bls.Scalar
}

func NewPrivateKey(pp *PublicParams) *PrivateKey {
	sk := new(PrivateKey)
	sk.Rs = make([]*bls.Scalar, pp.NumAttrs)
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
	newSk := NewPrivateKey(pp)

	r := blspairing.NewRandomScalar()

	newPk.g = new(bls.G1)
	newPk.g.ScalarMult(r, pk.g)
	newPk.gsig = new(bls.G1)
	newPk.gsig.ScalarMult(r, pk.gsig)

	newPk.h = new(bls.G1)
	newPk.h.ScalarMult(r, pk.h)
	newPk.hsig = new(bls.G1)
	newPk.hsig.ScalarMult(r, pk.hsig)

	newPk.u = new(bls.G1)
	newPk.u.ScalarMult(r, pk.u)
	newPk.usig = new(bls.G1)
	newPk.usig.ScalarMult(r, pk.usig)

	for i := 0; i < len(pk.es); i++ {
		newPk.es[i] = new(bls.G1)
		newPk.es[i].ScalarMult(r, pk.es[i])
		newPk.esigs[i] = new(bls.G1)
		newPk.esigs[i].ScalarMult(r, pk.esigs[i])
		newSk.Rs[i] = blspairing.CloneScalar(sk.Rs[i])
	}

	return newPk, newSk
}

type CertificateAuthority struct {
	pp *PublicParams
	mk *MasterKey
}

// Setup
func NewCertificateAuthority(pp *PublicParams) *CertificateAuthority {
	ca := new(CertificateAuthority)
	ca.pp = pp
	ca.mk = NewMasterKey(pp)
	return ca
}

func (ca *CertificateAuthority) MPK() *MPK {
	return ca.mk.MPK()
}

// GenCert,  ase_homosig_gen()
func (ca *CertificateAuthority) GenCert(attrs []bool) (*PublicKey, *PrivateKey) {
	pk := NewPublicKey(ca.pp)
	sk := NewPrivateKey(ca.pp)

	pk.g = blspairing.NewRandomG1()
	pk.h = blspairing.NewRandomG1()
	pk.u = blspairing.NewRandomG1()

	pk.gsig = ca.mk.GKeyPair.Sign(pk.g)
	pk.hsig = ca.mk.HKeyPair.Sign(pk.h)
	pk.usig = ca.mk.UKeyPair.Sign(pk.u)

	tmp := new(bls.G1)
	for i := 0; i < ca.pp.NumAttrs; i++ {
		sk.Rs[i] = blspairing.NewRandomScalar()
		pk.es[i] = new(bls.G1)
		if attrs[i] {
			pk.es[i].ScalarMult(sk.Rs[i], pk.h)
		} else {
			pk.es[i].ScalarMult(sk.Rs[i], pk.g)
		}

		tmp.Add(pk.es[i], pk.u)
		pk.esigs[i] = ca.mk.JKeyPairs[i].Sign(tmp)
	}

	return pk, sk
}

type Ciphertext struct {
	g   *bls.G1
	h   *bls.G1
	c2s []*bls.G1
}

func (ct *Ciphertext) String() string {
	sb := new(strings.Builder)

	fmt.Fprintf(sb, "{g: %v,\nh: %v,\nc2s: [\n", ct.g, ct.h)
	for i, c2 := range ct.c2s {
		fmt.Fprintf(sb, "\t[%d] %v,\n", i, c2)
	}
	fmt.Fprintf(sb, "}")

	return sb.String()
}

// Enc, ase_homosig_enc
// Note that len(plaintext) = 2 * numAttrs
func Encrypt(pp *PublicParams, pk *PublicKey, attrs []bool, plaintext []*bls.G1) *Ciphertext {
	ct := new(Ciphertext)

	s := blspairing.NewRandomScalar()
	ct.g = new(bls.G1)
	ct.g.ScalarMult(s, pk.g)

	t := blspairing.NewRandomScalar()
	ct.h = new(bls.G1)
	ct.h.ScalarMult(t, pk.h)

	idx := 0
	tmp := new(bls.G1)
	ct.c2s = make([]*bls.G1, 2*pp.NumAttrs)
	for i := 0; i < pp.NumAttrs; i++ {
		if attrs[i] {
			idx = 2*i + 1
			tmp.ScalarMult(t, pk.es[i])
		} else {
			idx = 2 * i
			tmp.ScalarMult(s, pk.es[i])
		}
		ct.c2s[idx] = new(bls.G1)
		ct.c2s[idx].Add(plaintext[idx], tmp)
	}

	return ct
}

// Dec, ase_homosig_dec
func Decrypt(pp *PublicParams, sk *PrivateKey, attrs []bool, ct *Ciphertext) []*bls.G1 {
	tmp := new(bls.G1)

	pt := make([]*bls.G1, pp.NumAttrs)
	for i := 0; i < pp.NumAttrs; i++ {
		pt[i] = new(bls.G1)
		if attrs[i] {
			tmp.ScalarMult(sk.Rs[i], ct.h)
			tmp.Neg()
			pt[i].Add(ct.c2s[2*i+1], tmp)
		} else {
			tmp.ScalarMult(sk.Rs[i], ct.g)
			tmp.Neg()
			pt[i].Add(ct.c2s[2*i], tmp)
		}
	}

	return pt
}
