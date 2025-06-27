package main

import (
	"fmt"

	"crypto/elliptic"
	"math/big"

	"github.com/etclab/mu"
	"github.com/etclab/ncircl/aggsig/bgls03"
	"github.com/etclab/ncircl/ecc"
	"github.com/etclab/ncircl/multisig/b03"
	"github.com/etclab/ncircl/multisig/bgoy07"
	"github.com/etclab/ncircl/pre/afgh05"
	"github.com/etclab/ncircl/pre/bbs98"
	"github.com/etclab/ncircl/pre/ch07"
	"github.com/etclab/ncircl/pre/lv08"
	"github.com/etclab/ncircl/util/blspairing"
	"github.com/etclab/ncircl/util/bytesx"
)

func sizeofECCPoint(p *ecc.Point) int {
	return len(p.X.Bytes()) + len(p.Y.Bytes())
}

func sizeofBigInt(k *big.Int) int {
	return len(k.Bytes())
}

func aggsig_bgls03() {
	var n int

	fmt.Println("\naggsig/bgls03")

	pp := bgls03.NewPublicParams()
	n = 0
	n += len(pp.G1.Bytes())
	n += len(pp.G2.Bytes())
	fmt.Printf("\tPublicParams: %d\n", n)
	n = 0
	n += len(pp.G1.BytesCompressed())
	n += len(pp.G2.BytesCompressed())
	fmt.Printf("\tPublicParams (compressed): %d\n", n)

	alicePK, aliceSK := bgls03.KeyGen(pp)
	fmt.Printf("\tPublicKey: %d\n", len(alicePK.V.Bytes()))
	fmt.Printf("\tPublicKey (compressed): %d\n", len(alicePK.V.BytesCompressed()))
	fmt.Printf("\tPrivateKey: %d\n", len(blspairing.ScalarToBytes(aliceSK.X)))

	msg := bytesx.Random(1024)
	aggSig := bgls03.NewSignature()
	bgls03.Sign(pp, aliceSK, msg, aggSig)
	fmt.Printf("\tSignature: %d\n", len(aggSig.Sig.Bytes()))
	fmt.Printf("\tSignature (compressed): %d\n", len(aggSig.Sig.BytesCompressed()))
}

func multisig_b03() {
	var n int

	fmt.Println("\nmultisig/b03")

	pp := b03.NewPublicParams()
	n = 0
	n += len(pp.G1.Bytes())
	n += len(pp.G2.Bytes())
	fmt.Printf("\tPublicParams: %d\n", n)
	n = 0
	n += len(pp.G1.BytesCompressed())
	n += len(pp.G2.BytesCompressed())
	fmt.Printf("\tPublicParams (compressed): %d\n", n)

	alicePK, aliceSK := b03.KeyGen(pp)
	fmt.Printf("\tPublicKey: %d\n", len(alicePK.V.Bytes()))
	fmt.Printf("\tPublicKey (compressed): %d\n", len(alicePK.V.BytesCompressed()))
	fmt.Printf("\tPrivateKey: %d\n", len(blspairing.ScalarToBytes(aliceSK.X)))

	msg := bytesx.Random(1024)
	muSig := b03.NewSignature()
	b03.Sign(pp, aliceSK, msg, muSig)
	fmt.Printf("\tSignature: %d\n", len(muSig.Sig.Bytes()))
	fmt.Printf("\tSignature (compressed): %d\n", len(muSig.Sig.BytesCompressed()))
}

func multisig_bgoy07() {
	var n int

	fmt.Println("\nmultisig/bgoy07")

	pp := bgoy07.NewPublicParams()
	n = 0
	n += len(pp.G1.Bytes())
	n += len(pp.G2.Bytes())
	fmt.Printf("\tPublicParams: %d\n", n)
	n = 0
	n += len(pp.G1.BytesCompressed())
	n += len(pp.G2.BytesCompressed())
	fmt.Printf("\tPublicParams (compressed): %d\n", n)

	alicePK, aliceSK := bgoy07.KeyGen(pp)
	n = 0
	n += len(alicePK.S.Bytes())
	n += len(alicePK.T.Bytes())
	n += len(alicePK.U.Bytes())
	fmt.Printf("\tPublicKey: %d\n", n)
	n = 0
	n += len(alicePK.S.BytesCompressed())
	n += len(alicePK.T.BytesCompressed())
	n += len(alicePK.U.BytesCompressed())
	fmt.Printf("\tPublicKey (compressed): %d\n", n)
	n = 0
	n += len(blspairing.ScalarToBytes(aliceSK.S))
	n += len(blspairing.ScalarToBytes(aliceSK.T))
	n += len(blspairing.ScalarToBytes(aliceSK.U))
	fmt.Printf("\tPrivateKey: %d\n", n)

	msg := bytesx.Random(1024)
	muSig := bgoy07.NewSignature()
	err := bgoy07.Sign(pp, aliceSK, msg, muSig, nil)
	if err != nil {
		mu.Fatalf("Alice sign failed: %v", err)
	}
	n = 0
	n += len(muSig.Q.Bytes())
	n += len(muSig.X.Bytes())
	n += len(muSig.Y.Bytes())
	n += len(muSig.R.Bytes())
	fmt.Printf("\tSignature: %d\n", n)
	n = 0
	n += len(muSig.Q.BytesCompressed())
	n += len(muSig.X.BytesCompressed())
	n += len(muSig.Y.BytesCompressed())
	n += len(muSig.R.BytesCompressed())
	fmt.Printf("\tSignature (compressed): %d\n", n)
}

func pre_afgh05() {
	var n int

	fmt.Println("\npre/afgh05")

	pp := afgh05.NewPublicParams()
	n = 0
	n += len(pp.G1.Bytes())
	n += len(pp.G2.Bytes())
	n += len(blspairing.GtToBytes(pp.Z))
	fmt.Printf("\tPublicParams: %d\n", n)
	n = 0
	n += len(pp.G1.BytesCompressed())
	n += len(pp.G2.BytesCompressed())
	n += len(blspairing.GtToBytes(pp.Z))
	fmt.Printf("\tPublicParams (compressed): %d\n", n)

	alicePK, aliceSK := afgh05.KeyGen(pp)
	n = 0
	n += len(alicePK.G1ToA.Bytes())
	n += len(alicePK.G2ToA.Bytes())
	fmt.Printf("\tPublicKey: %d\n", n)

	n = 0
	n += len(alicePK.G1ToA.BytesCompressed())
	n += len(alicePK.G2ToA.BytesCompressed())
	fmt.Printf("\tPublicKey (compressed): %d\n", n)

	n = 0
	n += len(blspairing.ScalarToBytes(aliceSK.A))
	fmt.Printf("\tPrivateKey: %d\n", n)

	bobPK, _ := afgh05.KeyGen(pp)

	rkAliceToBob := afgh05.ReEncryptionKeyGen(pp, aliceSK, bobPK)
	n = 0
	n += len(rkAliceToBob.RK.Bytes())
	fmt.Printf("\tReEncryptionKey: %d\n", n)

	n = 0
	n += len(rkAliceToBob.RK.BytesCompressed())
	fmt.Printf("\tReEncryptionKey (compressed): %d\n", n)

	msg := blspairing.NewRandomGt()

	ct1 := afgh05.Encrypt(pp, alicePK, msg)
	n = 0
	n += len(blspairing.GtToBytes(ct1.Alpha))
	n += len(ct1.Beta.Bytes())
	fmt.Printf("\tCiphertext1: %d\n", n)

	n = 0
	n += len(blspairing.GtToBytes(ct1.Alpha))
	n += len(ct1.Beta.BytesCompressed())
	fmt.Printf("\tCiphertext1 (compressed): %d\n", n)

	ct2 := afgh05.ReEncrypt(pp, rkAliceToBob, ct1)
	n = 0
	n += len(blspairing.GtToBytes(ct2.Alpha))
	n += len(blspairing.GtToBytes(ct2.Beta))
	fmt.Printf("\tCiphertext2: %d\n", n)
}

func pre_bbs98() {
	var n int

	fmt.Println("\npre/bbs98 (P-256)")

	pp := bbs98.NewPublicParams(elliptic.P256())

	alicePK, aliceSK := bbs98.KeyGen(pp)
	fmt.Printf("\tPublicKey: %d\n", sizeofECCPoint(&alicePK.Point))
	fmt.Printf("\tPrivateKey: %d\n", sizeofBigInt(aliceSK.K))

	_, bobSK := bbs98.KeyGen(pp)

	rkAliceToBob := bbs98.ReEncryptionKeyGen(pp, aliceSK, bobSK)
	fmt.Printf("\tReEncryptionKey: %d\n", sizeofBigInt(rkAliceToBob.RK))

	msg := ecc.NewRandomPoint(pp.Curve)

	ct, err := bbs98.Encrypt(pp, alicePK, msg)
	if err != nil {
		mu.Fatalf("Encrypt failed: %v\n", err)
	}
	n = sizeofECCPoint(ct.C1)
	n += sizeofECCPoint(ct.C2)
	fmt.Printf("\tCiphertext: %d\n", n)
}

func pre_ch07() {
	var n int

	fmt.Println("\npre/ch07")

	pp := ch07.NewPublicParams()
	n = 0
	n += len(pp.G1.Bytes())
	n += len(pp.G2.Bytes())
	fmt.Printf("\tPublicParams: %d\n", n)
	n = 0
	n += len(pp.G1.BytesCompressed())
	n += len(pp.G2.BytesCompressed())
	fmt.Printf("\tPublicParams (compressed): %d\n", n)

	alicePK, aliceSK := ch07.KeyGen(pp)
	n = 0
	n += len(alicePK.Y.Bytes())
	fmt.Printf("\tPublicKey: %d\n", n)
	n = 0
	n += len(alicePK.Y.BytesCompressed())
	fmt.Printf("\tPublicKey (compressed: %d\n", n)

	n = 0
	n += len(blspairing.ScalarToBytes(aliceSK.X))
	fmt.Printf("\tPrivateKey: %d\n", n)

	_, bobSK := ch07.KeyGen(pp)

	rkAliceToBob := ch07.ReEncryptionKeyGen(pp, aliceSK, bobSK)
	n = 0
	n += len(blspairing.ScalarToBytes(rkAliceToBob.RK))
	fmt.Printf("\tReEncryptionKey: %d\n", n)

	msg := blspairing.NewRandomGt()

	ct := ch07.Encrypt(pp, alicePK, msg)
	n = 0
	n += len(ct.A)
	n += len(ct.B.Bytes())
	n += len(blspairing.GtToBytes(ct.C))
	n += len(ct.D.Bytes())
	n += len(ct.E.Bytes())
	n += len(ct.S)
	fmt.Printf("\tCiphertext: %d\n", n)
	n = 0
	n += len(ct.A)
	n += len(ct.B.BytesCompressed())
	n += len(blspairing.GtToBytes(ct.C))
	n += len(ct.D.BytesCompressed())
	n += len(ct.E.BytesCompressed())
	n += len(ct.S)
	fmt.Printf("\tCiphertext (compressed): %d\n", n)
}

func pre_lv08() {
	var n, pubKeySize, pubKeySizeCompressed int
	fmt.Println("\npre/lv08")

	pp := lv08.NewPublicParams()
	n = 0
	n += len(pp.G1.Bytes())
	n += len(pp.G2.Bytes())
	fmt.Printf("\tPublicParams: %d\n", n)
	n = 0
	n += len(pp.G1.BytesCompressed())
	n += len(pp.G2.BytesCompressed())
	fmt.Printf("\tPublicParams (compressed): %d\n", n)

	alicePK, aliceSK := lv08.KeyGen(pp)
	pubKeySize = 0
	pubKeySize += len(alicePK.Y1.Bytes())
	pubKeySize += len(alicePK.Y2.Bytes())
	fmt.Printf("\tPublicKey: %d\n", pubKeySize)
	pubKeySizeCompressed = 0
	pubKeySizeCompressed += len(alicePK.Y1.BytesCompressed())
	pubKeySizeCompressed += len(alicePK.Y2.BytesCompressed())
	fmt.Printf("\tPublicKey (compressed): %d\n", pubKeySizeCompressed)

	fmt.Printf("\tPrivateKey: %d\n", len(blspairing.ScalarToBytes(aliceSK.X)))

	bobPK, _ := lv08.KeyGen(pp)

	rkAliceToBob := lv08.ReEncryptionKeyGen(pp, aliceSK, bobPK)
	fmt.Printf("\tReEncryptionKey: %d\n", pubKeySize+len(rkAliceToBob.RK.Bytes()))
	fmt.Printf("\tReEncryptionKey (compressed): %d\n", pubKeySizeCompressed+len(rkAliceToBob.RK.BytesCompressed()))

	msg := blspairing.NewRandomGt()

	ct2 := lv08.Encrypt2(pp, alicePK, msg)
	n = 0
	n += len(ct2.C1)
	n += len(ct2.C2.Bytes())
	n += len(blspairing.GtToBytes(ct2.C3))
	n += len(ct2.C4.Bytes())
	n += len(ct2.S)
	fmt.Printf("\tCiphertext2: %d\n", n)
	n = 0
	n += len(ct2.C1)
	n += len(ct2.C2.BytesCompressed())
	n += len(blspairing.GtToBytes(ct2.C3))
	n += len(ct2.C4.BytesCompressed())
	n += len(ct2.S)
	fmt.Printf("\tCiphertext2 (compressed): %d\n", n)

	ct1, err := lv08.ReEncrypt(pp, rkAliceToBob, ct2)
	if err != nil {
		mu.Fatalf("\tlv08.ReEncrypt failed: %v", err)
	}
	n = 0
	n += len(ct1.C1)
	n += len(ct1.C2Prime.Bytes())
	n += len(ct1.C2DoublePrime.Bytes())
	n += len(ct1.C2TriplePrime.Bytes())
	n += len(blspairing.GtToBytes(ct1.C3))
	n += len(ct1.C4.Bytes())
	n += len(ct1.S)
	fmt.Printf("\tCiphertext1: %d\n", n)
	n = 0
	n += len(ct1.C1)
	n += len(ct1.C2Prime.BytesCompressed())
	n += len(ct1.C2DoublePrime.BytesCompressed())
	n += len(ct1.C2TriplePrime.BytesCompressed())
	n += len(blspairing.GtToBytes(ct1.C3))
	n += len(ct1.C4.BytesCompressed())
	n += len(ct1.S)
	fmt.Printf("\tCiphertext1 (compressed): %d\n", n)
}

func main() {
	aggsig_bgls03()

	multisig_b03()
	multisig_bgoy07()

	pre_afgh05()
	pre_bbs98()
	pre_ch07()
	pre_lv08()
}
