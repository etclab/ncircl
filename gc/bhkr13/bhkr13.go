package bhkr13

import (
	"errors"
	"fmt"
	"os"

	"github.com/etclab/mu"
	"github.com/etclab/ncircl/util/aesx"
	"github.com/etclab/ncircl/util/bytesx"
	"github.com/etclab/ncircl/util/uint128"
)

var (
	ErrGarble = errors.New("bhkr13: an error occurred")
)

type GarbleGateType int

// src/garble.h::garble_gate_type_e enum
const (
	GarbleGateTypeEMPTY GarbleGateType = iota
	GarbleGateTypeZERO
	GarbleGateTypeONE
	GarbleGateTypeAND
	GarbleGateTypeOR
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
func NewGarbledCircuit(numInputs, numOutputs int, randAESKey []byte) *GarbledCircuit {
	var err error

	gc := new(GarbledCircuit)

	gc.NumInputs = numInputs
	gc.Outputs = make([]int, numOutputs)
	gc.OutputPerms = make([]bool, numOutputs)

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

// src/circuit_builder.c::gate_OR
func (gc *GarbledCircuit) GateOR(input0, input1, output int) {
	gc.gate(input0, input1, output, GarbleGateTypeOR)
}

// src/circuit_builder.c::gate_NOT
func (gc *GarbledCircuit) GateNOT(input0, input1, output int) {
	gc.gate(input0, input1, output, GarbleGateTypeNOT)
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
	if len(inputs) > 2 {
		for i := 2; i < len(inputs); i++ {
			wire := gc.NextWire()
			gc.GateAND(inputs[i], outputs[0], wire)
			outputs[0] = wire
		}
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
func (gc *GarbledCircuit) CreateInputLabels(labels []uint128.Uint128, delta uint128.Uint128) {
	for i := 0; i < len(labels); i += 2 {
		labels[i] = gc.randomBlock()
		labels[i+1] = uint128.Xor(labels[i], delta)
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

	fmt.Fprintln(os.Stderr, "A")

	table := gc.Table[idx-nxors:]

	fmt.Fprintln(os.Stderr, "B")

	if gate.Type == GarbleGateTypeXOR {
		*out0 = uint128.Xor(A0, B0)
		*out1 = uint128.Xor(*out0, delta)
	} else if gate.Type == GarbleGateTypeNOT {
		*out0 = A1
		*out1 = A0
	} else {
		fmt.Fprintln(os.Stderr, "C")
		var keys [4]uint128.Uint128
		var mask [4]uint128.Uint128
		var blocks [4]uint128.Uint128
		var newToken, newToken2 uint128.Uint128
		var label0, label1 *uint128.Uint128

		fmt.Fprintln(os.Stderr, "D")

		tweak := uint128.Uint128{H: uint64(idx), L: 0}
		lsb0 := A0.Lsb()
		lsb1 := B0.Lsb()

		fmt.Fprintln(os.Stderr, "E")

		A0 = garbleDouble(A0)
		A1 = garbleDouble(A1)
		B0 = garbleDouble(garbleDouble(B0))
		B1 = garbleDouble(garbleDouble(B1))

		fmt.Fprintln(os.Stderr, "F")

		keys[0] = uint128.Xor(uint128.Xor(A0, B0), tweak)
		keys[1] = uint128.Xor(uint128.Xor(A0, B1), tweak)
		keys[2] = uint128.Xor(uint128.Xor(A1, B0), tweak)
		keys[3] = uint128.Xor(uint128.Xor(A1, B1), tweak)

		fmt.Fprintln(os.Stderr, "G")

		// memcpy(mask, keys, sizeof mask)
		copy(mask[:], keys[:])

		fmt.Fprintln(os.Stderr, "H")

		// AES_ecb_encrypt_blks(keys, 4, key)
		keysBytes := make([]byte, 0, 512)
		keysBytes = append(keysBytes, keys[0].Bytes()...)
		keysBytes = append(keysBytes, keys[1].Bytes()...)
		keysBytes = append(keysBytes, keys[2].Bytes()...)
		keysBytes = append(keysBytes, keys[3].Bytes()...)
		fmt.Fprintln(os.Stderr, "I", len(keysBytes))
		aesx.EncryptECB(gc.GlobalKey.Bytes(), keysBytes, keysBytes)
		fmt.Fprintln(os.Stderr, "J")
		keys[0].SetBytes(keysBytes[:16])
		keys[1].SetBytes(keysBytes[16:32])
		keys[2].SetBytes(keysBytes[32:48])
		keys[3].SetBytes(keysBytes[48:])
		fmt.Fprintln(os.Stderr, "K")

		mask[0] = uint128.Xor(mask[0], keys[0])
		mask[1] = uint128.Xor(mask[1], keys[1])
		mask[2] = uint128.Xor(mask[2], keys[2])
		mask[3] = uint128.Xor(mask[2], keys[3])

		fmt.Fprintln(os.Stderr, "L")

		maskIdx := 2*lsb0 + lsb1
		newToken = mask[maskIdx]
		newToken2 = uint128.Xor(delta, newToken)
		label0 = out0
		label1 = out1

		fmt.Fprintln(os.Stderr, "M")

		if (lsb1 & lsb0) == 1 {
			*label0 = newToken2
			*label1 = newToken
		} else {
			*label0 = newToken
			*label1 = newToken2
		}

		fmt.Fprintln(os.Stderr, "O")

		blocks[0] = *label0
		blocks[1] = *label0
		blocks[2] = *label0
		blocks[3] = *label1

		fmt.Fprintln(os.Stderr, "P")

		// The problem is with the table indexing

		if (2*lsb0 + lsb1) != 0 {
			table[2*lsb0+lsb1-1] = uint128.Xor(blocks[0], mask[0])
		}
		fmt.Fprintln(os.Stderr, "Q")
		if (2*lsb0 + 1 - lsb1) != 0 {
			table[2*lsb0+1-lsb1-1] = uint128.Xor(blocks[1], mask[1])
		}
		fmt.Fprintf(os.Stderr, "R %d %d", 2*(1-lsb0)+lsb1-1, len(table))
		if (2*(1-lsb0) + lsb1) != 0 {
			table[2*(1-lsb0)+lsb1-1] = uint128.Xor(blocks[2], mask[2])
		}
		fmt.Fprintln(os.Stderr, "S")
		if (2*(1-lsb0) + (1 - lsb1)) != 0 {
			table[2*(1-lsb0)+(1-lsb1)-1] = uint128.Xor(blocks[3], mask[3])
		}
		fmt.Fprintln(os.Stderr, "T")
	}

	fmt.Fprintln(os.Stderr, "U")
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

// src/garble.c::garble_garble
func (gc *GarbledCircuit) Garble(inputLabels, outputLabels []uint128.Uint128) error {
	var delta uint128.Uint128

	gc.Wires = make([]uint128.Uint128, 2*gc.NumWires)
	gc.Table = make([]uint128.Uint128, len(gc.Gates)-gc.NumXors)

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
			gc.Wires[2*i+1] = uint128.Xor(gc.Wires[2*i], delta)
		}
	}

	fixedLabel := gc.randomBlock()
	gc.FixedLabel = fixedLabel

	fixedLabel.L &= 0xfe
	gc.Wires[2*gc.NumInputs] = fixedLabel
	gc.Wires[2*gc.NumInputs+1] = uint128.Xor(fixedLabel, delta)
	fixedLabel.L |= 0x01
	gc.Wires[2*(gc.NumInputs+1)] = uint128.Xor(fixedLabel, delta)
	gc.Wires[2*(gc.NumInputs+1)+1] = fixedLabel

	gc.GlobalKey = gc.randomBlock()

	gc.garbleStandard(delta)

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
	table := gc.Table[3*(idx-nxors):]

	if gate.Type == GarbleGateTypeXOR {
		*out = uint128.Xor(A, B)
	} else if gate.Type == GarbleGateTypeNOT {
		*out = A
	} else {
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

// src/eval.c::garble_eval
func (gc *GarbledCircuit) Eval(inputLabels, outputLabels []uint128.Uint128, outputs []bool) error {

	labels := make([]uint128.Uint128, gc.NumWires)

	// Set input wire labels
	copy(labels, inputLabels)

	// Set fixed wire labels
	fixedLabel := gc.FixedLabel
	fixedLabel.L &= 0xfe
	labels[gc.NumInputs] = fixedLabel
	fixedLabel.L |= 0x01
	labels[gc.NumInputs+1] = fixedLabel

	gc.evalStandard(labels)

	if outputLabels != nil {
		for i := 0; i < len(gc.Outputs); i++ {
			outputLabels[i] = labels[gc.Outputs[i]]
		}
	}

	if outputs != nil {
		for i := 0; i < len(gc.Outputs); i++ {
			tmp := labels[gc.Outputs[i]]
			tf := mu.IntToBool(tmp.Lsb())
			outputs[i] = tf != gc.OutputPerms[i] // xor operation
		}
	}

	return nil
}

// src/eval.c::garble_extract_labels
func ExtractLabels(extractedLabels, labels []uint128.Uint128, bits []bool, n int) {
	for i := 0; i < n; i++ {
		extractedLabels[i] = labels[2*i+mu.BoolToInt(bits[i])]
	}
}

// src/eval.c::garble_map_outputs
func MapOutputs(outputLabels, map_ []uint128.Uint128, vals []bool, m int) error {
	for i := 0; i < m; i++ {
		if map_[i] == outputLabels[2*i] {
			vals[i] = false
		} else if map_[i] == outputLabels[2*i+1] {
			vals[i] = true
		} else {
			return ErrGarble
		}
	}
	return nil
}
