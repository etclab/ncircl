package bhkr13

import (
	"testing"

	"github.com/etclab/ncircl/util/uint128"
)

// createTestGarbledCircuit creates a test garbled circuit for serialization testing
func createTestGarbledCircuit(garbleType GarbleType) *GarbledCircuit {
	numInputs := 3
	numOutputs := 2

	gc := NewGarbledCircuit(numInputs, numOutputs, garbleType, []byte("testkeyfor128bit"))
	gc.StartBuilding()

	// Create some gates for testing
	wire1 := gc.NextWire()
	gc.GateAND(0, 1, wire1)

	wire2 := gc.NextWire()
	gc.GateXOR(1, 2, wire2)

	wire3 := gc.NextWire()
	gc.GateAND(wire1, wire2, wire3)

	wire4 := gc.NextWire()
	gc.GateNOT(wire3, wire4)

	gc.FinishBuilding([]int{wire3, wire4})

	// Garble the circuit to populate all fields
	outputLabels := make([]uint128.Uint128, 2*numOutputs)
	err := gc.Garble(nil, outputLabels)
	if err != nil {
		panic("failed to garble test circuit: " + err.Error())
	}

	return gc
}

func TestGarbledCircuitMarshalUnmarshal(t *testing.T) {
	testCases := []struct {
		name       string
		garbleType GarbleType
	}{
		{"Standard", GarbleTypeStandard},
		{"HalfGates", GarbleTypeHalfGates},
		{"PrivacyFree", GarbleTypePrivacyFree},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create original circuit
			original := createTestGarbledCircuit(tc.garbleType)

			// Marshal
			data, err := original.Marshal()
			if err != nil {
				t.Fatalf("Marshal failed: %v", err)
			}

			// Unmarshal
			var reconstructed GarbledCircuit
			err = reconstructed.Unmarshal(data)
			if err != nil {
				t.Fatalf("Unmarshal failed: %v", err)
			}

			// Initialize runtime state
			err = reconstructed.InitializeRuntimeState([]byte("testkeyfor128bit"))
			if err != nil {
				t.Fatalf("InitializeRuntimeState failed: %v", err)
			}

			// Compare all serialized fields
			compareGarbledCircuits(t, original, &reconstructed)
		})
	}
}

func compareGarbledCircuits(t *testing.T, original, reconstructed *GarbledCircuit) {
	// Compare basic fields
	if original.Type != reconstructed.Type {
		t.Errorf("Type mismatch: got %v, want %v", reconstructed.Type, original.Type)
	}
	if original.NumInputs != reconstructed.NumInputs {
		t.Errorf("NumInputs mismatch: got %d, want %d", reconstructed.NumInputs, original.NumInputs)
	}
	if original.NumWires != reconstructed.NumWires {
		t.Errorf("NumWires mismatch: got %d, want %d", reconstructed.NumWires, original.NumWires)
	}
	if original.NumXors != reconstructed.NumXors {
		t.Errorf("NumXors mismatch: got %d, want %d", reconstructed.NumXors, original.NumXors)
	}

	// Compare Gates
	if len(original.Gates) != len(reconstructed.Gates) {
		t.Errorf("Gates length mismatch: got %d, want %d", len(reconstructed.Gates), len(original.Gates))
		return
	}
	for i, gate := range original.Gates {
		rGate := reconstructed.Gates[i]
		if gate.Type != rGate.Type {
			t.Errorf("Gate[%d].Type mismatch: got %v, want %v", i, rGate.Type, gate.Type)
		}
		if gate.Input0 != rGate.Input0 {
			t.Errorf("Gate[%d].Input0 mismatch: got %d, want %d", i, rGate.Input0, gate.Input0)
		}
		if gate.Input1 != rGate.Input1 {
			t.Errorf("Gate[%d].Input1 mismatch: got %d, want %d", i, rGate.Input1, gate.Input1)
		}
		if gate.Output != rGate.Output {
			t.Errorf("Gate[%d].Output mismatch: got %d, want %d", i, rGate.Output, gate.Output)
		}
	}

	// Compare Table
	if len(original.Table) != len(reconstructed.Table) {
		t.Errorf("Table length mismatch: got %d, want %d", len(reconstructed.Table), len(original.Table))
		return
	}
	for i, val := range original.Table {
		if val != reconstructed.Table[i] {
			t.Errorf("Table[%d] mismatch: got %v, want %v", i, reconstructed.Table[i], val)
		}
	}

	// Compare Wires
	if len(original.Wires) != len(reconstructed.Wires) {
		t.Errorf("Wires length mismatch: got %d, want %d", len(reconstructed.Wires), len(original.Wires))
		return
	}
	for i, val := range original.Wires {
		if val != reconstructed.Wires[i] {
			t.Errorf("Wires[%d] mismatch: got %v, want %v", i, reconstructed.Wires[i], val)
		}
	}

	// Compare Outputs
	if len(original.Outputs) != len(reconstructed.Outputs) {
		t.Errorf("Outputs length mismatch: got %d, want %d", len(reconstructed.Outputs), len(original.Outputs))
		return
	}
	for i, val := range original.Outputs {
		if val != reconstructed.Outputs[i] {
			t.Errorf("Outputs[%d] mismatch: got %d, want %d", i, reconstructed.Outputs[i], val)
		}
	}

	// Compare OutputPerms
	if len(original.OutputPerms) != len(reconstructed.OutputPerms) {
		t.Errorf("OutputPerms length mismatch: got %d, want %d", len(reconstructed.OutputPerms), len(original.OutputPerms))
		return
	}
	for i, val := range original.OutputPerms {
		if val != reconstructed.OutputPerms[i] {
			t.Errorf("OutputPerms[%d] mismatch: got %t, want %t", i, reconstructed.OutputPerms[i], val)
		}
	}

	// Compare FixedLabel and GlobalKey
	if original.FixedLabel != reconstructed.FixedLabel {
		t.Errorf("FixedLabel mismatch: got %v, want %v", reconstructed.FixedLabel, original.FixedLabel)
	}
	if original.GlobalKey != reconstructed.GlobalKey {
		t.Errorf("GlobalKey mismatch: got %v, want %v", reconstructed.GlobalKey, original.GlobalKey)
	}

	// Compare WireIndex
	if original.WireIndex != reconstructed.WireIndex {
		t.Errorf("WireIndex mismatch: got %d, want %d", reconstructed.WireIndex, original.WireIndex)
	}
}

func TestGarbledCircuitMarshalUnmarshalEmpty(t *testing.T) {
	// Test with empty circuit
	gc := NewGarbledCircuit(0, 0, GarbleTypeStandard, nil)

	data, err := gc.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var reconstructed GarbledCircuit
	err = reconstructed.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	compareGarbledCircuits(t, gc, &reconstructed)
}

func TestGarbledCircuitUnmarshalErrors(t *testing.T) {
	testCases := []struct {
		name string
		data []byte
	}{
		{"empty data", []byte{}},
		{"too short", []byte{1, 2, 3}},
		{"truncated after basic fields", make([]byte, 20)},
		{"invalid gates length", append(make([]byte, 20), 0xFF, 0xFF, 0xFF, 0xFF)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var gc GarbledCircuit
			err := gc.Unmarshal(tc.data)
			if err == nil {
				t.Error("Expected error but got nil")
			}
		})
	}
}

func TestInitializeRuntimeState(t *testing.T) {
	gc := &GarbledCircuit{}

	// Test with provided key
	key := []byte("testkeyfor128bit")
	err := gc.InitializeRuntimeState(key)
	if err != nil {
		t.Fatalf("InitializeRuntimeState failed: %v", err)
	}

	if gc.randAESECB == nil {
		t.Error("randAESECB should not be nil after initialization")
	}
	if gc.currentRandIndex != 0 {
		t.Errorf("currentRandIndex should be 0, got %d", gc.currentRandIndex)
	}

	// Test with nil key (should generate random key)
	gc2 := &GarbledCircuit{}
	err = gc2.InitializeRuntimeState(nil)
	if err != nil {
		t.Fatalf("InitializeRuntimeState with nil key failed: %v", err)
	}

	if gc2.randAESECB == nil {
		t.Error("randAESECB should not be nil after initialization with nil key")
	}
}

func TestGarbledCircuitSerializationFunctional(t *testing.T) {
	// Test that a serialized/deserialized circuit still works functionally
	numInputs := 2
	numOutputs := 1

	// Create and garble original circuit
	original := NewGarbledCircuit(numInputs, numOutputs, GarbleTypeStandard, nil)
	original.StartBuilding()
	wire := original.NextWire()
	original.GateAND(0, 1, wire)
	original.FinishBuilding([]int{wire})

	inputLabels := make([]uint128.Uint128, 2*numInputs)
	outputLabels := make([]uint128.Uint128, 2*numOutputs)
	err := original.Garble(inputLabels, outputLabels)
	if err != nil {
		t.Fatalf("Original garble failed: %v", err)
	}

	// Serialize and deserialize
	data, err := original.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var reconstructed GarbledCircuit
	err = reconstructed.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	err = reconstructed.InitializeRuntimeState(nil)
	if err != nil {
		t.Fatalf("InitializeRuntimeState failed: %v", err)
	}

	// Test evaluation with both circuits
	testInputs := []bool{true, true}
	extractedLabels := ExtractLabels(inputLabels, testInputs)

	// Evaluate with original
	originalOutputLabels := make([]uint128.Uint128, numOutputs)
	originalOutputs := make([]bool, numOutputs)
	err = original.Eval(extractedLabels, originalOutputLabels, originalOutputs)
	if err != nil {
		t.Fatalf("Original eval failed: %v", err)
	}

	// Evaluate with reconstructed
	reconstructedOutputLabels := make([]uint128.Uint128, numOutputs)
	reconstructedOutputs := make([]bool, numOutputs)
	err = reconstructed.Eval(extractedLabels, reconstructedOutputLabels, reconstructedOutputs)
	if err != nil {
		t.Fatalf("Reconstructed eval failed: %v", err)
	}

	// Compare results
	for i := range originalOutputs {
		if originalOutputs[i] != reconstructedOutputs[i] {
			t.Errorf("Output[%d] mismatch: original=%t, reconstructed=%t", i, originalOutputs[i], reconstructedOutputs[i])
		}
	}

	for i := range originalOutputLabels {
		if originalOutputLabels[i] != reconstructedOutputLabels[i] {
			t.Errorf("OutputLabel[%d] mismatch: original=%v, reconstructed=%v", i, originalOutputLabels[i], reconstructedOutputLabels[i])
		}
	}
}

// Benchmark tests
func BenchmarkGarbledCircuitMarshal(b *testing.B) {
	gc := createTestGarbledCircuit(GarbleTypeStandard)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := gc.Marshal()
		if err != nil {
			b.Fatalf("Marshal failed: %v", err)
		}
	}
}

func BenchmarkGarbledCircuitUnmarshal(b *testing.B) {
	gc := createTestGarbledCircuit(GarbleTypeStandard)
	data, err := gc.Marshal()
	if err != nil {
		b.Fatalf("Marshal failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var reconstructed GarbledCircuit
		err := reconstructed.Unmarshal(data)
		if err != nil {
			b.Fatalf("Unmarshal failed: %v", err)
		}
	}
}

func BenchmarkGarbledCircuitMarshalUnmarshal(b *testing.B) {
	gc := createTestGarbledCircuit(GarbleTypeStandard)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		data, err := gc.Marshal()
		if err != nil {
			b.Fatalf("Marshal failed: %v", err)
		}

		var reconstructed GarbledCircuit
		err = reconstructed.Unmarshal(data)
		if err != nil {
			b.Fatalf("Unmarshal failed: %v", err)
		}
	}
}

func TestOutputPermsBitPacking(t *testing.T) {
	// Test that OutputPerms boolean array is correctly packed and unpacked
	testCases := []struct {
		name        string
		outputPerms []bool
	}{
		{"empty", []bool{}},
		{"single true", []bool{true}},
		{"single false", []bool{false}},
		{"8 bits", []bool{true, false, true, true, false, true, false, false}},
		{"9 bits", []bool{true, false, true, true, false, true, false, false, true}},
		{"16 bits", []bool{true, false, true, true, false, true, false, false, true, false, true, true, false, true, false, false}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			gc := &GarbledCircuit{
				OutputPerms: tc.outputPerms,
			}

			data, err := gc.Marshal()
			if err != nil {
				t.Fatalf("Marshal failed: %v", err)
			}

			var reconstructed GarbledCircuit
			err = reconstructed.Unmarshal(data)
			if err != nil {
				t.Fatalf("Unmarshal failed: %v", err)
			}

			if len(reconstructed.OutputPerms) != len(tc.outputPerms) {
				t.Errorf("OutputPerms length mismatch: got %d, want %d", len(reconstructed.OutputPerms), len(tc.outputPerms))
				return
			}

			for i, expected := range tc.outputPerms {
				if reconstructed.OutputPerms[i] != expected {
					t.Errorf("OutputPerms[%d] mismatch: got %t, want %t", i, reconstructed.OutputPerms[i], expected)
				}
			}
		})
	}
}
