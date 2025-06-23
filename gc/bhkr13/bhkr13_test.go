package bhkr13

import (
	"fmt"
	"testing"

	"github.com/etclab/ncircl/util/uint128"
)

const Type = GarbleTypePrivacyFree

func TestGateAND(t *testing.T) {
	trials := []struct {
		input0   bool
		input1   bool
		expected bool
	}{
		{false, false, false},
		{false, true, false},
		{true, false, false},
		{true, true, true},
	}

	numInputs := 2
	numOutputs := 1

	inputLabels := make([]uint128.Uint128, 2*numInputs)
	outputLabels := make([]uint128.Uint128, 2*numOutputs)

	gc := NewGarbledCircuit(numInputs, numOutputs, Type, nil)
	gc.StartBuilding()
	wire := gc.NextWire()
	gc.GateAND(0, 1, wire)
	gc.FinishBuilding([]int{wire})

	err := gc.Garble(nil, outputLabels)
	if err != nil {
		t.Fatalf("gc.Garble failed: %v", err)
	}
	for i := 0; i < numInputs; i++ {
		inputLabels[2*i] = gc.Wires[2*i]
		inputLabels[2*i+1] = gc.Wires[2*i+1]
	}

	for _, trial := range trials {
		t.Run(fmt.Sprintf("%t-AND-%t", trial.input0, trial.input1), func(t *testing.T) {
			inputBits := []bool{trial.input0, trial.input1}
			computedOutputLabels := make([]uint128.Uint128, numOutputs)
			outputBits := make([]bool, numOutputs)

			extractedLabels := ExtractLabels(inputLabels, inputBits)
			err = gc.Eval(extractedLabels, computedOutputLabels, outputBits)
			if err != nil {
				t.Fatalf("gc.Eval failed: %v", err)
			}

			if outputBits[0] != trial.expected {
				t.Errorf("expected output of %t, but got %t", trial.expected, outputBits[0])
			}
		})
	}
}

func TestGateANDMapOutputs(t *testing.T) {
	trials := []struct {
		input0   bool
		input1   bool
		expected bool
	}{
		{false, false, false},
		{false, true, false},
		{true, false, false},
		{true, true, true},
	}

	numInputs := 2
	numOutputs := 1

	inputLabels := make([]uint128.Uint128, 2*numInputs)
	outputLabels := make([]uint128.Uint128, 2*numOutputs)

	gc := NewGarbledCircuit(numInputs, numOutputs, Type, nil)
	gc.StartBuilding()
	wire := gc.NextWire()
	gc.GateAND(0, 1, wire)
	gc.FinishBuilding([]int{wire})

	err := gc.Garble(nil, outputLabels)
	if err != nil {
		t.Fatalf("gc.Garble failed: %v", err)
	}
	for i := 0; i < numInputs; i++ {
		inputLabels[2*i] = gc.Wires[2*i]
		inputLabels[2*i+1] = gc.Wires[2*i+1]
	}

	for _, trial := range trials {
		t.Run(fmt.Sprintf("%t-AND-%t", trial.input0, trial.input1), func(t *testing.T) {
			inputBits := []bool{trial.input0, trial.input1}
			computedOutputLabels := make([]uint128.Uint128, numOutputs)

			extractedLabels := ExtractLabels(inputLabels, inputBits)
			err = gc.Eval(extractedLabels, computedOutputLabels, nil)
			if err != nil {
				t.Fatalf("gc.Eval failed: %v", err)
			}

			outputBits, err := MapOutputs(outputLabels, computedOutputLabels)
			if err != nil {
				t.Fatalf("MapOutputs failed: %v", err)
			}

			if outputBits[0] != trial.expected {
				t.Errorf("expected map output of %t, but got %t", trial.expected, outputBits[0])
			}
		})
	}
}

func TestGateXOR(t *testing.T) {
	trials := []struct {
		input0   bool
		input1   bool
		expected bool
	}{
		{false, false, false},
		{false, true, true},
		{true, false, true},
		{true, true, false},
	}

	numInputs := 2
	numOutputs := 1

	inputLabels := make([]uint128.Uint128, 2*numInputs)
	outputLabels := make([]uint128.Uint128, 2*numOutputs)

	gc := NewGarbledCircuit(numInputs, numOutputs, Type, nil)
	gc.StartBuilding()
	wire := gc.NextWire()
	gc.GateXOR(0, 1, wire)
	gc.FinishBuilding([]int{wire})

	err := gc.Garble(nil, outputLabels)
	if err != nil {
		t.Fatalf("gc.Garble failed: %v", err)
	}
	for i := 0; i < numInputs; i++ {
		inputLabels[2*i] = gc.Wires[2*i]
		inputLabels[2*i+1] = gc.Wires[2*i+1]
	}

	for _, trial := range trials {
		t.Run(fmt.Sprintf("%t-XOR-%t", trial.input0, trial.input1), func(t *testing.T) {
			inputBits := []bool{trial.input0, trial.input1}
			computedOutputLabels := make([]uint128.Uint128, numOutputs)
			outputBits := make([]bool, numOutputs)

			extractedLabels := ExtractLabels(inputLabels, inputBits)
			err = gc.Eval(extractedLabels, computedOutputLabels, outputBits)
			if err != nil {
				t.Fatalf("gc.Eval failed: %v", err)
			}

			if outputBits[0] != trial.expected {
				t.Errorf("expected output of %t, but got %t", trial.expected, outputBits[0])
			}
		})
	}
}

func TestGateXORMapOutputs(t *testing.T) {
	trials := []struct {
		input0   bool
		input1   bool
		expected bool
	}{
		{false, false, false},
		{false, true, true},
		{true, false, true},
		{true, true, false},
	}

	numInputs := 2
	numOutputs := 1

	inputLabels := make([]uint128.Uint128, 2*numInputs)
	outputLabels := make([]uint128.Uint128, 2*numOutputs)

	gc := NewGarbledCircuit(numInputs, numOutputs, Type, nil)
	gc.StartBuilding()
	wire := gc.NextWire()
	gc.GateXOR(0, 1, wire)
	gc.FinishBuilding([]int{wire})

	err := gc.Garble(nil, outputLabels)
	if err != nil {
		t.Fatalf("gc.Garble failed: %v", err)
	}
	for i := 0; i < numInputs; i++ {
		inputLabels[2*i] = gc.Wires[2*i]
		inputLabels[2*i+1] = gc.Wires[2*i+1]
	}

	for _, trial := range trials {
		t.Run(fmt.Sprintf("%t-XOR-%t", trial.input0, trial.input1), func(t *testing.T) {
			inputBits := []bool{trial.input0, trial.input1}
			computedOutputLabels := make([]uint128.Uint128, numOutputs)

			extractedLabels := ExtractLabels(inputLabels, inputBits)
			err = gc.Eval(extractedLabels, computedOutputLabels, nil)
			if err != nil {
				t.Fatalf("gc.Eval failed: %v", err)
			}

			outputBits, err := MapOutputs(outputLabels, computedOutputLabels)
			if err != nil {
				t.Fatalf("MapOutputs failed: %v", err)
			}

			if outputBits[0] != trial.expected {
				t.Errorf("expected map output of %t, but got %t", trial.expected, outputBits[0])
			}
		})
	}
}

func TestGateNOT(t *testing.T) {
	trials := []struct {
		input0   bool
		expected bool
	}{
		{false, true},
		{true, false},
	}

	numInputs := 1
	numOutputs := 1

	inputLabels := make([]uint128.Uint128, 2*numInputs)
	outputLabels := make([]uint128.Uint128, 2*numOutputs)

	gc := NewGarbledCircuit(numInputs, numOutputs, Type, nil)
	gc.StartBuilding()
	wire := gc.NextWire()
	gc.GateNOT(0, wire)
	gc.FinishBuilding([]int{wire})

	err := gc.Garble(nil, outputLabels)
	if err != nil {
		t.Fatalf("gc.Garble failed: %v", err)
	}
	for i := 0; i < numInputs; i++ {
		inputLabels[2*i] = gc.Wires[2*i]
		inputLabels[2*i+1] = gc.Wires[2*i+1]
	}

	for _, trial := range trials {
		t.Run(fmt.Sprintf("NOT-%t", trial.input0), func(t *testing.T) {
			inputBits := []bool{trial.input0}
			computedOutputLabels := make([]uint128.Uint128, numOutputs)
			outputBits := make([]bool, numOutputs)

			extractedLabels := ExtractLabels(inputLabels, inputBits)
			err = gc.Eval(extractedLabels, computedOutputLabels, outputBits)
			if err != nil {
				t.Fatalf("gc.Eval failed: %v", err)
			}

			if outputBits[0] != trial.expected {
				t.Errorf("expected output of %t, but got %t", trial.expected, outputBits[0])
			}
		})
	}
}

func TestGateNOTMapOutputs(t *testing.T) {
	trials := []struct {
		input0   bool
		expected bool
	}{
		{false, true},
		{true, false},
	}

	numInputs := 1
	numOutputs := 1

	inputLabels := make([]uint128.Uint128, 2*numInputs)
	outputLabels := make([]uint128.Uint128, 2*numOutputs)

	gc := NewGarbledCircuit(numInputs, numOutputs, Type, nil)
	gc.StartBuilding()
	wire := gc.NextWire()
	gc.GateNOT(0, wire)
	gc.FinishBuilding([]int{wire})

	err := gc.Garble(nil, outputLabels)
	if err != nil {
		t.Fatalf("gc.Garble failed: %v", err)
	}
	for i := 0; i < numInputs; i++ {
		inputLabels[2*i] = gc.Wires[2*i]
		inputLabels[2*i+1] = gc.Wires[2*i+1]
	}

	for _, trial := range trials {
		t.Run(fmt.Sprintf("NOT-%t", trial.input0), func(t *testing.T) {
			inputBits := []bool{trial.input0}
			computedOutputLabels := make([]uint128.Uint128, numOutputs)

			extractedLabels := ExtractLabels(inputLabels, inputBits)
			err = gc.Eval(extractedLabels, computedOutputLabels, nil)
			if err != nil {
				t.Fatalf("gc.Eval failed: %v", err)
			}

			outputBits, err := MapOutputs(outputLabels, computedOutputLabels)
			if err != nil {
				t.Fatalf("MapOutputs failed: %v", err)
			}

			if outputBits[0] != trial.expected {
				t.Errorf("expected map output of %t, but got %t", trial.expected, outputBits[0])
			}
		})
	}
}
