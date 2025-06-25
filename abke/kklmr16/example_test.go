package kklmr16_test

import (
	"fmt"
	"log"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/etclab/mu"
	"github.com/etclab/ncircl/abke/kklmr16"
	"github.com/etclab/ncircl/gc/bhkr13"
	"github.com/etclab/ncircl/util/aesx"
	"github.com/etclab/ncircl/util/blspairing"
	"github.com/etclab/ncircl/util/uint128"
)

func Example() {
	pp := kklmr16.NewPublicParams(4)
	ca := kklmr16.NewCertificateAuthority(pp)

	attrs := []bool{true, false, false, true}
	pk, sk := ca.GenCert(attrs)

	// generate random plaintext
	pt := make([]*bls.G1, pp.NumAttrs*2)
	for i := 0; i < len(pt); i++ {
		pt[i] = blspairing.NewRandomG1()
	}

	ct := kklmr16.Encrypt(pp, pk, nil, pt)

	got := kklmr16.Decrypt(pp, sk, ct)

	fmt.Printf("%v %v %v %v\n",
		got[0].IsEqual(pt[1]),
		got[1].IsEqual(pt[2]),
		got[2].IsEqual(pt[4]),
		got[3].IsEqual(pt[7]))
	// Output:
	// true true true true
}

func buildANDPolicy(gc *bhkr13.GarbledCircuit, numInputs int) {
	inputWires := make([]int, numInputs)
	for i := 0; i < len(inputWires); i++ {
		inputWires[i] = i
	}
	outputWires := make([]int, 1)
	gc.StartBuilding()
	gc.CircuitAND(inputWires, outputWires)
	gc.FinishBuilding(outputWires)
}

// Example_KeyExchange demonstrates how abke can be combined with garbled circuits
// (gc/bhkr13) to achieve an attribute-based key exchange.
func Example_simulateKeyExchange() {
	// setup the system
	numAttrs := 2
	pp := kklmr16.NewPublicParams(numAttrs)
	ca := kklmr16.NewCertificateAuthority(pp)
	mpk := ca.MPK()

	// CA issues keypair to client Alice
	alicePK, aliceSK := ca.GenCert([]bool{true, true})

	// server builds the garbled circuit
	ttables := make([]uint128.Uint128, 2*pp.NumAttrs)
	inputLabels := make([]uint128.Uint128, 2*pp.NumAttrs)
	outputLabels := make([]uint128.Uint128, 2)

	gc := bhkr13.NewGarbledCircuit(pp.NumAttrs, 1, bhkr13.GarbleTypeStandard, nil)
	buildANDPolicy(gc, pp.NumAttrs)

	err := gc.Garble(nil, outputLabels)
	if err != nil {
		log.Fatalf("gc.Garble failed: %v", err)
	}

	for i := 0; i < numAttrs; i++ {
		inputLabels[2*i] = gc.Wires[2*i]
		inputLabels[2*i+1] = gc.Wires[2*i+1]
	}

	// server generates random ASE (Attribute Select Encryption) plaintext
	asePTs := make([]*bls.G1, 2*pp.NumAttrs)
	for i := 0; i < len(asePTs); i++ {
		asePTs[i] = blspairing.NewRandomG1()
	}

	// server encrypts the garbled circuit input labels with an AES key derived
	// from each ASE plaintext element
	for i := range asePTs {
		key := kklmr16.Hash(asePTs[i], i/2, (i%2) == 1)
		tmp := inputLabels[i].Bytes()
		aesx.EncryptECB(key.Bytes(), tmp, tmp)
		var encryptedInputLabel uint128.Uint128
		encryptedInputLabel.SetBytes(tmp)
		ttables[i] = encryptedInputLabel
	}

	// server receives the client's public key and verifies that it is valid
	if !alicePK.Verify(pp, mpk) {
		log.Fatal("alice's public key is invalid; aborting connection")
	}

	// server encrypts the ASE plaintext to the client's public key;
	ct := kklmr16.Encrypt(pp, alicePK, nil, asePTs)

	// TODO: server creates commitment

	// the server would then send the ciphertext ct and commmitment comm to the
	// client

	// client decrypts the ciphertext; the resultant "plaintext" is the
	// AES-encrypted input labels
	aseDec := kklmr16.Decrypt(pp, aliceSK, ct)

	// client AES-decrypts the input labels that correspond to its
	// attributes
	aliceInputLabels := make([]uint128.Uint128, numAttrs)
	for i := 0; i < numAttrs; i++ {
		key := kklmr16.Hash(aseDec[i], i, aliceSK.Attrs[i])
		tmp := ttables[2*i+mu.BoolToInt(aliceSK.Attrs[i])]
		tmpData := tmp.Bytes()
		aesx.DecryptECB(key.Bytes(), tmpData, tmpData)

		var decryptedInputLabel uint128.Uint128
		decryptedInputLabel.SetBytes(tmpData)
		aliceInputLabels[i] = decryptedInputLabel
	}

}
