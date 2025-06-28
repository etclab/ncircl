package bhkr13

import (
	"errors"

	"github.com/etclab/mu"
	"github.com/etclab/ncircl/util/aesx"
	"github.com/etclab/ncircl/util/bytesx"
	"github.com/etclab/ncircl/util/uint128"
)

var (
	ErrUnknown = errors.New("bhkr13: an unexpected error occurred")
)

const f15e1 = 0xfffffffffffffffe

type GarbleType int

const (
	// GRR3 and free-XOR as used in JustGarble
	GarbleTypeStandard GarbleType = iota

	// Half-gates approach of Zahur, Rosulek, and Evans (Eurocrypt 2015)
	GarbleTypeHalfGates

	// Privacy-free approach of Zahur, Rosulek, and Evans (Eurocrypt 2015)
	GarbleTypePrivacyFree
)

func (gt GarbleType) String() string {
	switch gt {
	case GarbleTypeStandard:
		return "standard"
	case GarbleTypeHalfGates:
		return "half-gates"
	case GarbleTypePrivacyFree:
		return "privacy-free"
	default:
		mu.BUG("uknown GarbleType %d", gt)
	}

	return "ERROR-Uknown-Garble-Type" // NOTREACHED: appease compiler
}

type GarbleGateType int

// src/garble.h::garble_gate_type_e enum
const (
	GarbleGateTypeEMPTY GarbleGateType = iota
	GarbleGateTypeAND
	GarbleGateTypeXOR
	GarbleGateTypeNOT
)

// src/garble.h::garble_gate struct
type GarbleGate struct {
	// Type is the type of gate this is
	Type GarbleGateType

	// Input0 is the index of the first input wire for this gate
	Input0 int

	// Input1 is the index of the second input wire for this gate
	Input1 int

	// ouput is the index of the ouput wire for this gate
	Output int
}

// GarbleContext is the context info for building a circuit description.
type GarbleContext struct {
	WireIndex int
}

// src/garble.h::garble_circuit
type GarbledCircuit struct {
	// Type is the garbling scheme type
	Type GarbleType

	// NumInputs is the number of inputs (`n` in libgarble)
	NumInputs int

	// NumGates is the number of gates (q) - just use len(Gates)

	// NumWires is the number of wires (`r` in libgarble)
	NumWires int

	// NumXors is teh number of xor gates (`nxors` in libgarble)
	NumXors int

	Gates []GarbleGate // len: q

	Table []uint128.Uint128 // garble_table_size = (q - nxors) * (3 * sizeof(block))

	Wires []uint128.Uint128 // length: 2 * r

	Outputs []int // length: m

	// OutputPerms is the permutation bits of the output wire lables
	OutputPerms []bool // m elements

	// FixedLabe lis used for constant values
	FixedLabel uint128.Uint128

	// GloblaKey is the key used for fixed-key AES.
	GlobalKey uint128.Uint128

	randAESECB *aesx.ECB

	currentRandIndex int

	GarbleContext
}

// src/gc.c::garble_new
func NewGarbledCircuit(numInputs, numOutputs int, type_ GarbleType, randAESKey []byte) *GarbledCircuit {
	var err error

	gc := new(GarbledCircuit)

	gc.NumInputs = numInputs
	gc.Outputs = make([]int, numOutputs)
	gc.OutputPerms = make([]bool, numOutputs)
	gc.Type = type_

	// this is essentially the logic for src/block.c:garble_seed
	if randAESKey == nil {
		randAESKey = bytesx.Random(16)
	}
	gc.randAESECB, err = aesx.NewECB(randAESKey)
	if err != nil {
		mu.BUG("aesx.NewECB failed: %v", err)
	}

	return gc
}

// src/circuit_builder.c::builder_start_building
func (gc *GarbledCircuit) StartBuilding() {
	// start at first non-input, non-fixed wire
	gc.WireIndex = gc.NumInputs + 2
}

// src/circuit_builder.c::builder_finish_building
func (gc *GarbledCircuit) FinishBuilding(outputs []int) {
	gc.NumWires = gc.WireIndex
	for i := 0; i < len(gc.Outputs); i++ {
		gc.Outputs[i] = outputs[i]
	}
}

// src/circuit_builder.c::builder_next_wire
func (gc *GarbledCircuit) NextWire() int {
	index := gc.WireIndex
	gc.WireIndex += 1
	return index
}

// src/circuit_builder.c::_gate
func (gc *GarbledCircuit) gate(input0, input1, output int, typ GarbleGateType) {
	gate := GarbleGate{
		Type:   typ,
		Input0: input0,
		Input1: input1,
		Output: output,
	}
	gc.Gates = append(gc.Gates, gate)
}

// src/circuit_builder.c::gate_AND
func (gc *GarbledCircuit) GateAND(input0, input1, output int) {
	gc.gate(input0, input1, output, GarbleGateTypeAND)
}

// src/circuit_builder.c::gate_XOR
func (gc *GarbledCircuit) GateXOR(input0, input1, output int) {
	gc.NumXors += 1
	gc.gate(input0, input1, output, GarbleGateTypeXOR)
}

// src/circuit_builder.c::gate_NOT
func (gc *GarbledCircuit) GateNOT(input0, output int) {
	gc.gate(input0, input0, output, GarbleGateTypeNOT)
}

// src/circuit_builder.c::wire_zero
func (gc *GarbledCircuit) WireZero() int {
	return gc.NumInputs
}

// src/circuit_builder.c::wire_one
func (gc *GarbledCircuit) WireOne() int {
	return gc.NumInputs + 1
}

// src/circuit_builder.c::circuit_and
func (gc *GarbledCircuit) CircuitAND(inputs, outputs []int) {
	if len(inputs) < 2 {
		mu.BUG("inputs must have len >= 2; got %d", len(inputs))
	}

	outputs[0] = gc.NextWire()
	gc.GateAND(inputs[0], inputs[1], outputs[0])
	for i := 2; i < len(inputs); i++ {
		wire := gc.NextWire()
		gc.GateAND(inputs[i], outputs[0], wire)
		outputs[0] = wire
	}
}

// src/circuit_builder.c::circuit_or
func (gc *GarbledCircuit) CircuitOR(inputs, outputs []int) {
	if gc.Type != GarbleTypeStandard {
		mu.BUG("CircuitOR is currently only supported for GarbleTypeStandard")
	}
	if len(inputs) < 2 {
		mu.BUG("inputs must have len >= 2; got %d", len(inputs))
	}

	a := gc.NextWire()
	gc.GateNOT(inputs[0], a)
	b := gc.NextWire()
	gc.GateNOT(inputs[1], b)
	c := gc.NextWire()
	gc.GateAND(a, b, c)
	outputs[0] = gc.NextWire()
	gc.GateNOT(c, outputs[0])
	for i := 2; i < len(inputs); i++ {
		a = gc.NextWire()
		gc.GateNOT(outputs[0], a)
		b = gc.NextWire()
		gc.GateNOT(inputs[i], b)
		c = gc.NextWire()
		gc.GateAND(a, b, c)
		outputs[0] = gc.NextWire()
		gc.GateNOT(c, outputs[0])
	}
}

// src/garble/block.h::garble_double
func garbleDouble(x uint128.Uint128) uint128.Uint128 {
	return uint128.SllEpi64(x, 1)
}

// The random block is just the AES encryption of the currentRandINdex
// src/block.c::garble_random_block
func (gc *GarbledCircuit) randomBlock() uint128.Uint128 {
	out := uint128.Uint128{
		H: 0,
		L: uint64(gc.currentRandIndex),
	}

	gc.currentRandIndex += 1

	outBytes := out.Bytes()
	err := gc.randAESECB.Encrypt(outBytes, outBytes)
	if err != nil {
		mu.BUG("ecb.Encrypt failed: %v", err)
	}
	out.SetBytes(outBytes)

	return out
}

// src/garble.c::garble_creat_deleta
func (gc *GarbledCircuit) CreateDelta() uint128.Uint128 {
	delta := gc.randomBlock()
	delta.L |= 1
	return delta
}

// src/garble.c::createInputLabels
func (gc *GarbledCircuit) CreateInputLabels(labels []uint128.Uint128, delta *uint128.Uint128) {
	var delta_ uint128.Uint128
	if delta == nil {
		delta_ = gc.CreateDelta()
	} else {
		delta_ = *delta
	}
	for i := 0; i < len(labels); i += 2 {
		labels[i] = gc.randomBlock()
		if gc.Type == GarbleTypePrivacyFree {
			labels[i].L &= 15e1
		}
		labels[i+1] = uint128.Xor(labels[i], delta_)
	}
}

// src/garble/garble_gate_standard.h::garble_gate_garble_standard
func (gc *GarbledCircuit) garbleStandardGate(gate GarbleGate, delta uint128.Uint128, idx, nxors int) {
	A0 := gc.Wires[2*gate.Input0]
	A1 := gc.Wires[2*gate.Input0+1]
	B0 := gc.Wires[2*gate.Input1]
	B1 := gc.Wires[2*gate.Input1+1]
	out0 := &gc.Wires[2*gate.Output]
	out1 := &gc.Wires[2*gate.Output+1]

	if gate.Type == GarbleGateTypeXOR {
		*out0 = uint128.Xor(A0, B0)
		*out1 = uint128.Xor(*out0, delta)
	} else if gate.Type == GarbleGateTypeNOT {
		*out0 = A1
		*out1 = A0
	} else {
		table := gc.Table[3*(idx-nxors):]
		var keys [4]uint128.Uint128
		var mask [4]uint128.Uint128
		var blocks [4]uint128.Uint128
		var newToken, newToken2 uint128.Uint128
		var label0, label1 *uint128.Uint128

		tweak := uint128.Uint128{H: uint64(idx), L: 0}
		lsb0 := A0.Lsb()
		lsb1 := B0.Lsb()

		A0 = garbleDouble(A0)
		A1 = garbleDouble(A1)
		B0 = garbleDouble(garbleDouble(B0))
		B1 = garbleDouble(garbleDouble(B1))

		keys[0] = uint128.Xor(uint128.Xor(A0, B0), tweak)
		keys[1] = uint128.Xor(uint128.Xor(A0, B1), tweak)
		keys[2] = uint128.Xor(uint128.Xor(A1, B0), tweak)
		keys[3] = uint128.Xor(uint128.Xor(A1, B1), tweak)

		// memcpy(mask, keys, sizeof mask)
		copy(mask[:], keys[:])

		// AES_ecb_encrypt_blks(keys, 4, key)
		keysBytes := make([]byte, 0, 64)
		keysBytes = append(keysBytes, keys[0].Bytes()...)
		keysBytes = append(keysBytes, keys[1].Bytes()...)
		keysBytes = append(keysBytes, keys[2].Bytes()...)
		keysBytes = append(keysBytes, keys[3].Bytes()...)
		aesx.EncryptECB(gc.GlobalKey.Bytes(), keysBytes, keysBytes)
		keys[0].SetBytes(keysBytes[:16])
		keys[1].SetBytes(keysBytes[16:32])
		keys[2].SetBytes(keysBytes[32:48])
		keys[3].SetBytes(keysBytes[48:])

		mask[0] = uint128.Xor(mask[0], keys[0])
		mask[1] = uint128.Xor(mask[1], keys[1])
		mask[2] = uint128.Xor(mask[2], keys[2])
		mask[3] = uint128.Xor(mask[3], keys[3])

		maskIdx := 2*lsb0 + lsb1
		newToken = mask[maskIdx]
		newToken2 = uint128.Xor(delta, newToken)
		label0 = out0
		label1 = out1

		if (lsb1 & lsb0) == 1 {
			*label0 = newToken2
			*label1 = newToken
		} else {
			*label0 = newToken
			*label1 = newToken2
		}

		blocks[0] = *label0
		blocks[1] = *label0
		blocks[2] = *label0
		blocks[3] = *label1

		if (2*lsb0 + lsb1) != 0 {
			table[2*lsb0+lsb1-1] = uint128.Xor(blocks[0], mask[0])
		}
		if (2*lsb0 + 1 - lsb1) != 0 {
			table[2*lsb0+1-lsb1-1] = uint128.Xor(blocks[1], mask[1])
		}
		if (2*(1-lsb0) + lsb1) != 0 {
			table[2*(1-lsb0)+lsb1-1] = uint128.Xor(blocks[2], mask[2])
		}
		if (2*(1-lsb0) + (1 - lsb1)) != 0 {
			table[2*(1-lsb0)+(1-lsb1)-1] = uint128.Xor(blocks[3], mask[3])
		}
	}
}

// src/garble.c//_garble_standard
func (gc *GarbledCircuit) garbleStandard(delta uint128.Uint128) {
	nxors := 0
	for i, gate := range gc.Gates {
		if gate.Type == GarbleGateTypeXOR {
			nxors += 1
		}
		gc.garbleStandardGate(gate, delta, i, nxors)
	}
}

// src/garble/garble_gate_halfgates.h::garble_gate_garble_gate_halfgates
func (gc *GarbledCircuit) garbleHalfGate(gate GarbleGate, delta uint128.Uint128, idx, nxors int) {
	A0 := gc.Wires[2*gate.Input0]
	A1 := gc.Wires[2*gate.Input0+1]
	B0 := gc.Wires[2*gate.Input1]
	B1 := gc.Wires[2*gate.Input1+1]
	out0 := &gc.Wires[2*gate.Output]
	out1 := &gc.Wires[2*gate.Output+1]

	if gate.Type == GarbleGateTypeXOR {
		*out0 = uint128.Xor(A0, B0)
		*out1 = uint128.Xor(*out0, delta)
	} else if gate.Type == GarbleGateTypeNOT {
		*out0 = A1
		*out1 = A0
	} else {
		table := gc.Table[2*(idx-nxors):]

		pa := A0.Lsb()
		pb := B0.Lsb()

		tweak1 := uint128.Uint128{H: uint64(2 * idx), L: 0}
		tweak2 := uint128.Uint128{H: uint64(2*idx + 1), L: 0}

		var keys [4]uint128.Uint128
		var masks [4]uint128.Uint128

		keys[0] = uint128.Xor(garbleDouble(A0), tweak1)
		keys[1] = uint128.Xor(garbleDouble(A1), tweak1)
		keys[2] = uint128.Xor(garbleDouble(B0), tweak2)
		keys[3] = uint128.Xor(garbleDouble(B1), tweak2)
		copy(masks[:], keys[:])

		// AES_ecb_encrypt_blks(keys, 4, key)
		keysBytes := make([]byte, 0, 64)
		keysBytes = append(keysBytes, keys[0].Bytes()...)
		keysBytes = append(keysBytes, keys[1].Bytes()...)
		keysBytes = append(keysBytes, keys[2].Bytes()...)
		keysBytes = append(keysBytes, keys[3].Bytes()...)
		aesx.EncryptECB(gc.GlobalKey.Bytes(), keysBytes, keysBytes)
		keys[0].SetBytes(keysBytes[:16])
		keys[1].SetBytes(keysBytes[16:32])
		keys[2].SetBytes(keysBytes[32:48])
		keys[3].SetBytes(keysBytes[48:])

		HA0 := uint128.Xor(keys[0], masks[0])
		HA1 := uint128.Xor(keys[1], masks[1])
		HB0 := uint128.Xor(keys[2], masks[2])
		HB1 := uint128.Xor(keys[3], masks[3])

		table[0] = uint128.Xor(HA0, HA1)
		if pb == 1 {
			table[0] = uint128.Xor(table[0], delta)
		}

		W0 := HA0
		if pa == 1 {
			W0 = uint128.Xor(W0, table[0])
		}

		tmp := uint128.Xor(HB0, HB1)
		table[1] = uint128.Xor(tmp, A0)
		W0 = uint128.Xor(W0, HB0)
		if pb == 1 {
			W0 = uint128.Xor(W0, tmp)

		}

		*out0 = W0
		*out1 = uint128.Xor(*out0, delta)
	}
}

// src/garble.c//_garble_halfgates
func (gc *GarbledCircuit) garbleHalfGates(delta uint128.Uint128) {
	nxors := 0
	for i, gate := range gc.Gates {
		if gate.Type == GarbleGateTypeXOR {
			nxors += 1
		}
		gc.garbleHalfGate(gate, delta, i, nxors)
	}
}

// src/garble/garble_gate_privacy_free.h::garble_gate_garble_privacy_free
func (gc *GarbledCircuit) garblePrivacyFreeGate(gate GarbleGate, delta uint128.Uint128, idx, nxors int) {
	A0 := gc.Wires[2*gate.Input0]
	A1 := gc.Wires[2*gate.Input0+1]
	B0 := gc.Wires[2*gate.Input1]
	B1 := gc.Wires[2*gate.Input1+1]
	out0 := &gc.Wires[2*gate.Output]
	out1 := &gc.Wires[2*gate.Output+1]

	mu.UNUSED(B1)

	if gate.Type == GarbleGateTypeXOR {
		*out0 = uint128.Xor(A0, B0)
		*out1 = uint128.Xor(*out0, delta)
	} else if gate.Type == GarbleGateTypeNOT {
		*out0 = A1
		*out1 = A0
	} else {
		table := gc.Table[(idx - nxors):]
		var masks [2]uint128.Uint128

		tweak := uint128.Uint128{H: uint64(2 * idx), L: 0}
		var keys [2]uint128.Uint128

		keys[0] = uint128.Xor(garbleDouble(A0), tweak)
		keys[1] = uint128.Xor(garbleDouble(A1), tweak)
		copy(masks[:], keys[:])
		keysBytes := make([]byte, 0, 32)
		keysBytes = append(keysBytes, keys[0].Bytes()...)
		keysBytes = append(keysBytes, keys[1].Bytes()...)
		aesx.EncryptECB(gc.GlobalKey.Bytes(), keysBytes, keysBytes)
		keys[0].SetBytes(keysBytes[:16])
		keys[1].SetBytes(keysBytes[16:32])
		HA0 := uint128.Xor(keys[0], masks[0])
		HA1 := uint128.Xor(keys[1], masks[1])

		HA0.L &= f15e1
		HA1.L |= 0x1
		tmp := uint128.Xor(HA0, HA1)
		table[0] = uint128.Xor(tmp, B0)
		*out0 = HA0
		*out1 = uint128.Xor(HA0, delta)
	}
}

// src/garble.c//_garble_privacy_free
func (gc *GarbledCircuit) garblePrivacyFree(delta uint128.Uint128) {
	nxors := 0
	for i, gate := range gc.Gates {
		if gate.Type == GarbleGateTypeXOR {
			nxors += 1
		}
		gc.garblePrivacyFreeGate(gate, delta, i, nxors)
	}
}

// src/garble.c::garble_garble
func (gc *GarbledCircuit) Garble(inputLabels, outputLabels []uint128.Uint128) error {
	var delta uint128.Uint128

	gc.Wires = make([]uint128.Uint128, 2*gc.NumWires)

	switch gc.Type {
	case GarbleTypeStandard:
		gc.Table = make([]uint128.Uint128, 3*(len(gc.Gates)-gc.NumXors))
	case GarbleTypeHalfGates:
		gc.Table = make([]uint128.Uint128, 2*(len(gc.Gates)-gc.NumXors))
	case GarbleTypePrivacyFree:
		gc.Table = make([]uint128.Uint128, len(gc.Gates)-gc.NumXors)
	default:
		mu.BUG("bad gc.Type: %v", gc.Type)
	}

	if inputLabels != nil {
		for i := 0; i < gc.NumInputs; i++ {
			gc.Wires[2*i] = inputLabels[2*i]
			gc.Wires[2*i+1] = inputLabels[2*i+1]
		}
		// assumes same delta for all 0/1 lables in `inputs`
		delta = uint128.Xor(gc.Wires[0], gc.Wires[1])
	} else {
		delta = gc.CreateDelta()
		for i := 0; i < gc.NumInputs; i++ {
			gc.Wires[2*i] = gc.randomBlock()
			if gc.Type == GarbleTypePrivacyFree {
				// zero lable should have 0 permutation bit
				gc.Wires[2*i].L &= f15e1
			}
			gc.Wires[2*i+1] = uint128.Xor(gc.Wires[2*i], delta)
		}
		// SMH: added
		//delta = uint128.Xor(gc.Wires[0], gc.Wires[1])
	}

	fixedLabel := gc.randomBlock()
	gc.FixedLabel = fixedLabel

	fixedLabel.L &= f15e1
	gc.Wires[2*gc.NumInputs] = fixedLabel
	gc.Wires[2*gc.NumInputs+1] = uint128.Xor(fixedLabel, delta)
	fixedLabel.L |= 0x01
	// SMH: not symmetric?
	gc.Wires[2*(gc.NumInputs+1)] = uint128.Xor(fixedLabel, delta)
	gc.Wires[2*(gc.NumInputs+1)+1] = fixedLabel

	gc.GlobalKey = gc.randomBlock()

	switch gc.Type {
	case GarbleTypeStandard:
		gc.garbleStandard(delta)
	case GarbleTypeHalfGates:
		gc.garbleHalfGates(delta)
	case GarbleTypePrivacyFree:
		gc.garblePrivacyFree(delta)
	default:
		mu.BUG("bad gc.Type %v", gc.Type)
	}

	for i := 0; i < len(gc.Outputs); i++ {
		tmp := gc.Wires[2*gc.Outputs[i]]
		gc.OutputPerms[i] = mu.IntToBool(tmp.Lsb())
	}

	if outputLabels != nil {
		for i := 0; i < len(gc.Outputs); i++ {
			outputLabels[2*i] = gc.Wires[2*gc.Outputs[i]]
			outputLabels[2*i+1] = gc.Wires[2*gc.Outputs[i]+1]
		}
	}

	return nil
}

// src/garble/garble_gate_standard.h::garble_gate_eval_standard
func (gc *GarbledCircuit) evalStandardGate(gate GarbleGate, labels []uint128.Uint128, idx, nxors int) {
	A := labels[gate.Input0]
	B := labels[gate.Input1]
	out := &labels[gate.Output]

	if gate.Type == GarbleGateTypeXOR {
		*out = uint128.Xor(A, B)
	} else if gate.Type == GarbleGateTypeNOT {
		*out = A
	} else {
		table := gc.Table[3*(idx-nxors):]
		a := A.Lsb()
		b := B.Lsb()

		HA := garbleDouble(A)
		HB := garbleDouble(garbleDouble(B))

		tweak := uint128.Uint128{H: uint64(idx), L: 0}
		val := uint128.Xor(uint128.Xor(HA, HB), tweak)

		var tmp uint128.Uint128
		if (a + b) > 0 {
			tmp = uint128.Xor(table[2*a+b-1], val)
		} else {
			tmp = val
		}

		valBytes := val.Bytes()
		aesx.EncryptECB(gc.GlobalKey.Bytes(), valBytes, valBytes)
		val.SetBytes(valBytes)

		*out = uint128.Xor(val, tmp)
	}
}

// src/eval.c::_eval_standard
func (gc *GarbledCircuit) evalStandard(labels []uint128.Uint128) {
	nxors := 0
	for i, gate := range gc.Gates {
		if gate.Type == GarbleGateTypeXOR {
			nxors += 1
		}
		gc.evalStandardGate(gate, labels, i, nxors)
	}
}

// src/garble/garble_gate_halfgatesh::garble_gate_eval_halfgates
func (gc *GarbledCircuit) evalHalfGate(gate GarbleGate, labels []uint128.Uint128, idx, nxors int) {
	A := labels[gate.Input0]
	B := labels[gate.Input1]
	out := &labels[gate.Output]

	if gate.Type == GarbleGateTypeXOR {
		*out = uint128.Xor(A, B)
	} else if gate.Type == GarbleGateTypeNOT {
		*out = A
	} else {
		table := gc.Table[2*(idx-nxors):]
		sa := A.Lsb()
		sb := B.Lsb()

		tweak1 := uint128.Uint128{H: uint64(2 * idx), L: 0}
		tweak2 := uint128.Uint128{H: uint64(2*idx + 1), L: 0}

		keys := make([]uint128.Uint128, 2)
		masks := make([]uint128.Uint128, 2)

		keys[0] = uint128.Xor(garbleDouble(A), tweak1)
		keys[1] = uint128.Xor(garbleDouble(B), tweak2)
		copy(masks[:], keys[:])

		// AES_ecb_encrypt_blocks(keys, 2, key)
		keysBytes := make([]byte, 0, 32)
		keysBytes = append(keysBytes, keys[0].Bytes()...)
		keysBytes = append(keysBytes, keys[1].Bytes()...)
		aesx.EncryptECB(gc.GlobalKey.Bytes(), keysBytes, keysBytes)
		keys[0].SetBytes(keysBytes[:16])
		keys[1].SetBytes(keysBytes[16:])

		HA := uint128.Xor(keys[0], masks[0])
		HB := uint128.Xor(keys[1], masks[1])

		W := uint128.Xor(HA, HB)
		if sa == 1 {
			W = uint128.Xor(W, table[0])
		}
		if sb == 1 {
			W = uint128.Xor(W, table[1])
			W = uint128.Xor(W, A)
		}
		*out = W
	}
}

// src/eval.c::_eval_halfgates
func (gc *GarbledCircuit) evalHalfGates(labels []uint128.Uint128) {
	nxors := 0
	for i, gate := range gc.Gates {
		if gate.Type == GarbleGateTypeXOR {
			nxors += 1
		}
		gc.evalHalfGate(gate, labels, i, nxors)
	}
}

// src/garble/garble_gate_privacy_free.h::garble_gate_eval_privacy_free
func (gc *GarbledCircuit) evalPrivacyFreeGate(gate GarbleGate, labels []uint128.Uint128, idx, nxors int) {
	A := labels[gate.Input0]
	B := labels[gate.Input1]
	out := &labels[gate.Output]

	if gate.Type == GarbleGateTypeXOR {
		*out = uint128.Xor(A, B)
	} else if gate.Type == GarbleGateTypeNOT {
		*out = A
	} else {
		table := gc.Table[(idx - nxors):]
		sa := A.Lsb()
		tweak := uint128.Uint128{H: uint64(2 * idx), L: 0}

		tmp := uint128.Xor(garbleDouble(A), tweak)
		mask := tmp

		tmpBytes := tmp.Bytes()
		aesx.EncryptECB(gc.GlobalKey.Bytes(), tmpBytes, tmpBytes)
		tmp.SetBytes(tmpBytes)
		HA := uint128.Xor(tmp, mask)

		var W uint128.Uint128
		if sa == 1 {
			HA.L |= 1
			W = uint128.Xor(HA, table[0])
			W = uint128.Xor(W, B)
		} else {
			HA.L &= f15e1
			W = HA
		}
		*out = W
	}
}

// src/eval.c::_eval_privacy_free
func (gc *GarbledCircuit) evalPrivacyFree(labels []uint128.Uint128) {
	nxors := 0
	for i, gate := range gc.Gates {
		if gate.Type == GarbleGateTypeXOR {
			nxors += 1
		}
		gc.evalPrivacyFreeGate(gate, labels, i, nxors)
	}
}

// src/eval.c::garble_eval
func (gc *GarbledCircuit) Eval(inputLabels, outputLabels []uint128.Uint128, outputs []bool) error {

	labels := make([]uint128.Uint128, gc.NumWires)

	// Set input wire labels
	copy(labels, inputLabels)

	// Set fixed wire labels
	fixedLabel := gc.FixedLabel
	fixedLabel.L &= f15e1
	labels[gc.NumInputs] = fixedLabel
	fixedLabel.L |= 0x01
	labels[gc.NumInputs+1] = fixedLabel

	switch gc.Type {
	case GarbleTypeStandard:
		gc.evalStandard(labels)
	case GarbleTypeHalfGates:
		gc.evalHalfGates(labels)
	case GarbleTypePrivacyFree:
		gc.evalPrivacyFree(labels)
	default:
		mu.BUG("bad gc.Type: %v", gc.Type)
	}

	if outputLabels != nil {
		for i := 0; i < len(gc.Outputs); i++ {
			outputLabels[i] = labels[gc.Outputs[i]]
		}
	}

	if outputs != nil {
		for i := 0; i < len(gc.Outputs); i++ {
			tmp := labels[gc.Outputs[i]]
			tf := mu.IntToBool(tmp.Lsb())
			outputs[i] = (tf != gc.OutputPerms[i]) // xor operation
		}
	}

	return nil
}

// src/eval.c::garble_extract_labels
func ExtractLabels(inputLabels []uint128.Uint128, bits []bool) []uint128.Uint128 {
	if 2*len(bits) != len(inputLabels) {
		mu.BUG("bhkr13: number of inputs labels is not twice the number of input bits (%d xinput lables and %d input bits)", len(inputLabels), len(bits))
	}

	n := len(inputLabels) / 2
	extractedLabels := make([]uint128.Uint128, n)
	for i := 0; i < n; i++ {
		extractedLabels[i] = inputLabels[2*i+mu.BoolToInt(bits[i])]
	}

	return extractedLabels
}

// src/eval.c::garble_map_outputs
func MapOutputs(outputLabels, computedOutputs []uint128.Uint128) ([]bool, error) {
	if 2*len(computedOutputs) != len(outputLabels) {
		mu.BUG("bhkr13: number of output labels is not twice the number of computed outputs (%d output lables and %d computed outputs)", len(outputLabels), len(computedOutputs))
	}

	outputs := make([]bool, len(computedOutputs))
	for i := 0; i < len(computedOutputs); i++ {
		if computedOutputs[i] == outputLabels[2*i] {
			outputs[i] = false
		} else if computedOutputs[i] == outputLabels[2*i+1] {
			outputs[i] = true
		} else {
			return nil, ErrUnknown
		}
	}
	return outputs, nil
}
