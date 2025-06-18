package bhkr13

import (
	"github.com/etclab/mu"
	"github.com/etclab/ncircl/util/aesx"
	"github.com/etclab/ncircl/util/uint128"
)

type GarbleGateType int

const (
	GarbleGateTypeXor GarbleGateType = iota
	GarbleGateTypeNot
)

type GarbledCircuit struct {
	// NumInputs is the number of inputs (n)
	NumInputs int

	// NumOutpus is the number of outputs (m)
	NumOutputs int

	// NumGates is the number of gates (q)
	NumGates int

	// Gates

	// Table

	// Wires

	// Outputs

	// OuputPerms
}

// garble_new
func NewGarbledCircuit(n, m int) *GarbledCircuit {
	gc := &GarbledCircuit{
		NumInputs:  n,
		NumOutputs: m,
	}

	return gc
}

func garbleDouble(x uint128.Uint128) uint128.Uint128 {
	return uint128.SllEpi64(x, 1)
}

// src/garble/garble_gate_standard.h::garble_gate_garble_standard
func GarbleStandardGate(typ GarbleGateType, A0, A1, B0, B1, delta uint128.Uint128, idx uint64, aesKey []byte) (uint128.Uint128, uint128.Uint128) {
	var out0, out1 uint128.Uint128

	if typ == GarbleGateTypeXor {
		out0 = uint128.Xor(A0, B0)
		out1 = uint128.Xor(out0, delta)
	} else if typ == GarbleGateTypeNot {
		out0 = A1
		out1 = A0
	} else {
		var keys [4]uint128.Uint128
		var mask [4]uint128.Uint128
		var blocks [4]uint128.Uint128
		mu.UNUSED(blocks)

		tweak := uint128.Uint128{H: idx, L: 0}
		lsb0 := A0.Lsb()
		lsb1 := B0.Lsb()
		mu.UNUSED(lsb0)
		mu.UNUSED(lsb1)

		A0 = garbleDouble(A0)
		A1 = garbleDouble(A1)
		B0 = garbleDouble(garbleDouble(B0))
		B1 = garbleDouble(garbleDouble(B1))

		keys[0] = uint128.Xor(uint128.Xor(A0, B0), tweak)
		keys[1] = uint128.Xor(uint128.Xor(A0, B1), tweak)
		keys[2] = uint128.Xor(uint128.Xor(A1, B0), tweak)
		keys[3] = uint128.Xor(uint128.Xor(A1, B1), tweak)

		// memcpy(mask, keys, sizeof mask)
		mask[0] = keys[0]
		mask[1] = keys[1]
		mask[2] = keys[2]
		mask[3] = keys[3]

		keysBytes := make([]byte, 0, 512)
		keysBytes = append(keysBytes, keys[0].Bytes()...)
		keysBytes = append(keysBytes, keys[1].Bytes()...)
		keysBytes = append(keysBytes, keys[2].Bytes()...)
		keysBytes = append(keysBytes, keys[3].Bytes()...)
		aesx.EncryptECB(aesKey, keysBytes, keysBytes)
		keys[0].SetBytes(keysBytes[:128])
		keys[1].SetBytes(keysBytes[128:256])
		keys[2].SetBytes(keysBytes[256:384])
		keys[3].SetBytes(keysBytes[384:])

		mask[0] = uint128.Xor(mask[0], keys[0])
		mask[1] = uint128.Xor(mask[1], keys[1])
		mask[2] = uint128.Xor(mask[2], keys[2])
		mask[3] = uint128.Xor(mask[2], keys[3])

		// newToken = mask[2 *lsb0 + lsb1]
		// ...
	}

	return out0, out1
}

// src/garble/garble_gate_standard.h::garble_gate_eval_standard
func EvalStandardGate(typ GarbleGateType, A, B uint128.Uint128, idx uint64, aesKey []byte) uint128.Uint128 {
	var out uint128.Uint128
	if typ == GarbleGateTypeXor {
		out = uint128.Xor(A, B)
	} else if typ == GarbleGateTypeNot {
		out = A
	} else {
		a := A.Lsb()
		b := B.Lsb()
		mu.UNUSED(a)
		mu.UNUSED(b)

		HA := garbleDouble(A)
		HB := garbleDouble(garbleDouble(B))

		tweak := uint128.Uint128{H: idx, L: 0}
		val := uint128.Xor(uint128.Xor(HA, HB), tweak)
		// TODO: tmp = a + b ? garble_xor(table[2*a+b-1], val) : val;
		valBytes := val.Bytes()
		aesx.EncryptECB(aesKey, valBytes, valBytes)
		val.SetBytes(valBytes)

		//out = uint128.Xor(val, tmp)
	}

	return out
}

/*

func (gc *GarbledCircuit) AndGate() {

}

func (gc *GarbledCircuit) OrGate() {

}

func (gc *GarbledCircuit) XorGate() {

}

func (gc *GarbledCircuit) NotGate() {

}

// garble_garble
//
//	garble_xor
//	garble_random_block
//	_garble_standard
func (gc *GarbledCircuit) Garble(inputLabels, outputLabels []*Blocks) {

}

// garble_eval
func (gc *GarbledCircuit) Evaluate(inputLabels, outputLabels []*Blocks) []bool {

}
*/
