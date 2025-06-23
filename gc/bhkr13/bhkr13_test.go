package bhkr13

import (
	"crypto/rand"
	"fmt"
	"strings"
	"testing"

	"github.com/etclab/mu"
	"github.com/etclab/ncircl/util/uint128"
)

var garbleTypes = []GarbleType{GarbleTypeStandard, GarbleTypePrivacyFree}

func subtestName(inputBits []bool) string {
	strs := make([]string, len(inputBits))
	for i, b := range inputBits {
		if b {
			strs[i] = "1"
		} else {
			strs[i] = "0"
		}
	}

	return strings.Join(strs, "")
}

func randomInputBits(n int) []bool {
	inputBits := make([]bool, n)
	var b [1]byte

	for i := 0; i < n; i++ {
		// get a random byte
		_, err := rand.Read(b[:])
		if err != nil {
			mu.Panicf("rand.Read failed: %v", err)
		}

		// extract lowest bit
		bit := b[0] & 1

		inputBits[i] = mu.IntToBool(int(bit))
	}

	return inputBits
}

func andBits(bits []bool) bool {
	for _, b := range bits {
		if b == false {
			return false
		}
	}
	return true
}

func TestGateAND(t *testing.T) {
	trials := []struct {
		inputBits []bool
		expected  bool
	}{
		{[]bool{false, false}, false},
		{[]bool{false, true}, false},
		{[]bool{true, false}, false},
		{[]bool{true, true}, true},
	}

	numInputs := 2
	numOutputs := 1

	for _, garbleType := range garbleTypes {
		inputLabels := make([]uint128.Uint128, 2*numInputs)
		outputLabels := make([]uint128.Uint128, 2*numOutputs)
		gc := NewGarbledCircuit(numInputs, numOutputs, garbleType, nil)
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
			t.Run(fmt.Sprintf("%v/%s", garbleType, subtestName(trial.inputBits)), func(t *testing.T) {
				computedOutputLabels := make([]uint128.Uint128, numOutputs)
				outputBits := make([]bool, numOutputs)

				extractedLabels := ExtractLabels(inputLabels, trial.inputBits)
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
}

func TestGateANDMapOutputs(t *testing.T) {
	trials := []struct {
		inputBits []bool
		expected  bool
	}{
		{[]bool{false, false}, false},
		{[]bool{false, true}, false},
		{[]bool{true, false}, false},
		{[]bool{true, true}, true},
	}

	numInputs := 2
	numOutputs := 1

	for _, garbleType := range garbleTypes {
		inputLabels := make([]uint128.Uint128, 2*numInputs)
		outputLabels := make([]uint128.Uint128, 2*numOutputs)

		gc := NewGarbledCircuit(numInputs, numOutputs, garbleType, nil)
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
			t.Run(fmt.Sprintf("%v/%s", garbleType, subtestName(trial.inputBits)), func(t *testing.T) {
				computedOutputLabels := make([]uint128.Uint128, numOutputs)

				extractedLabels := ExtractLabels(inputLabels, trial.inputBits)
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
}

func TestGateXOR(t *testing.T) {
	trials := []struct {
		inputBits []bool
		expected  bool
	}{
		{[]bool{false, false}, false},
		{[]bool{false, true}, true},
		{[]bool{true, false}, true},
		{[]bool{true, true}, false},
	}

	numInputs := 2
	numOutputs := 1

	for _, garbleType := range garbleTypes {
		inputLabels := make([]uint128.Uint128, 2*numInputs)
		outputLabels := make([]uint128.Uint128, 2*numOutputs)

		gc := NewGarbledCircuit(numInputs, numOutputs, garbleType, nil)
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
			t.Run(fmt.Sprintf("%v/%s", garbleType, subtestName(trial.inputBits)), func(t *testing.T) {
				computedOutputLabels := make([]uint128.Uint128, numOutputs)
				outputBits := make([]bool, numOutputs)

				extractedLabels := ExtractLabels(inputLabels, trial.inputBits)
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
}

func TestGateXORMapOutputs(t *testing.T) {
	trials := []struct {
		inputBits []bool
		expected  bool
	}{
		{[]bool{false, false}, false},
		{[]bool{false, true}, true},
		{[]bool{true, false}, true},
		{[]bool{true, true}, false},
	}

	numInputs := 2
	numOutputs := 1

	for _, garbleType := range garbleTypes {
		inputLabels := make([]uint128.Uint128, 2*numInputs)
		outputLabels := make([]uint128.Uint128, 2*numOutputs)

		gc := NewGarbledCircuit(numInputs, numOutputs, garbleType, nil)
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
			t.Run(fmt.Sprintf("%v/%s", garbleType, subtestName(trial.inputBits)), func(t *testing.T) {
				computedOutputLabels := make([]uint128.Uint128, numOutputs)

				extractedLabels := ExtractLabels(inputLabels, trial.inputBits)
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
}

func TestGateNOT(t *testing.T) {
	trials := []struct {
		inputBits []bool
		expected  bool
	}{
		{[]bool{false}, true},
		{[]bool{true}, false},
	}

	numInputs := 1
	numOutputs := 1

	for _, garbleType := range garbleTypes {
		inputLabels := make([]uint128.Uint128, 2*numInputs)
		outputLabels := make([]uint128.Uint128, 2*numOutputs)

		gc := NewGarbledCircuit(numInputs, numOutputs, garbleType, nil)
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
			t.Run(fmt.Sprintf("%v/%s", garbleType, subtestName(trial.inputBits)), func(t *testing.T) {
				computedOutputLabels := make([]uint128.Uint128, numOutputs)
				outputBits := make([]bool, numOutputs)

				extractedLabels := ExtractLabels(inputLabels, trial.inputBits)
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
}

func TestGateNOTMapOutputs(t *testing.T) {
	trials := []struct {
		inputBits []bool
		expected  bool
	}{
		{[]bool{false}, true},
		{[]bool{true}, false},
	}

	numInputs := 1
	numOutputs := 1

	for _, garbleType := range garbleTypes {
		inputLabels := make([]uint128.Uint128, 2*numInputs)
		outputLabels := make([]uint128.Uint128, 2*numOutputs)

		gc := NewGarbledCircuit(numInputs, numOutputs, garbleType, nil)
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
			t.Run(fmt.Sprintf("%v/%s", garbleType, subtestName(trial.inputBits)), func(t *testing.T) {
				computedOutputLabels := make([]uint128.Uint128, numOutputs)

				extractedLabels := ExtractLabels(inputLabels, trial.inputBits)
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
}

func TestCircuitAND(t *testing.T) {
	trials := []struct {
		inputBits []bool
		expected  bool
	}{
		{[]bool{false, false}, false},
		{[]bool{false, true}, false},
		{[]bool{true, false}, false},
		{[]bool{true, true}, true},

		// just a few examples, not exhaustive
		{[]bool{false, false, false}, false},
		{[]bool{false, true, false}, false},
		{[]bool{true, true, false}, false},
		{[]bool{true, true, true}, true},

		// just a few examples, not exhaustive
		{[]bool{false, false, false, false}, false},
		{[]bool{false, true, false, false}, false},
		{[]bool{true, true, true, false}, false},
		{[]bool{true, true, true, true}, true},
	}

	numOutputs := 1

	for _, garbleType := range garbleTypes {
		for _, trial := range trials {
			numInputs := len(trial.inputBits)
			inputLabels := make([]uint128.Uint128, 2*numInputs)
			outputLabels := make([]uint128.Uint128, 2*numOutputs)
			gc := NewGarbledCircuit(numInputs, numOutputs, garbleType, nil)
			gc.StartBuilding()

			inputWires := make([]int, numInputs)
			for i := 0; i < len(inputWires); i++ {
				inputWires[i] = i
			}
			outputWires := make([]int, numOutputs)

			gc.CircuitAND(inputWires, outputWires)
			gc.FinishBuilding(outputWires)

			err := gc.Garble(nil, outputLabels)
			if err != nil {
				t.Fatalf("gc.Garble failed: %v", err)
			}
			for i := 0; i < numInputs; i++ {
				inputLabels[2*i] = gc.Wires[2*i]
				inputLabels[2*i+1] = gc.Wires[2*i+1]
			}

			t.Run(fmt.Sprintf("%v/%s", garbleType, subtestName(trial.inputBits)), func(t *testing.T) {
				computedOutputLabels := make([]uint128.Uint128, numOutputs)
				outputBits := make([]bool, numOutputs)

				extractedLabels := ExtractLabels(inputLabels, trial.inputBits)
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
}

func BenchmarkGarbleCircuitAND(b *testing.B) {

	numOutputs := 1

	for _, garbleType := range garbleTypes {
		for numInputs := 2; numInputs < 32; numInputs++ {
			b.Run(fmt.Sprintf("%v/numInputs:%d", garbleType, numInputs), func(b *testing.B) {
				inputLabels := make([]uint128.Uint128, 2*numInputs)
				outputLabels := make([]uint128.Uint128, 2*numOutputs)
				gc := NewGarbledCircuit(numInputs, numOutputs, garbleType, nil)
				gc.StartBuilding()

				inputWires := make([]int, numInputs)
				for i := 0; i < len(inputWires); i++ {
					inputWires[i] = i
				}
				outputWires := make([]int, numOutputs)

				gc.CircuitAND(inputWires, outputWires)
				gc.FinishBuilding(outputWires)

				for b.Loop() {
					err := gc.Garble(nil, outputLabels)
					if err != nil {
						b.Fatalf("gc.Garble failed: %v", err)
					}
					for i := 0; i < numInputs; i++ {
						inputLabels[2*i] = gc.Wires[2*i]
						inputLabels[2*i+1] = gc.Wires[2*i+1]
					}
				}
			})
		}
	}
}

func BenchmarkEvalCircuitAND(b *testing.B) {

	numOutputs := 1

	for _, garbleType := range garbleTypes {
		for numInputs := 2; numInputs < 32; numInputs++ {
			b.Run(fmt.Sprintf("%v/numInputs:%d", garbleType, numInputs), func(b *testing.B) {
				inputBits := randomInputBits(numInputs)
				expected := andBits(inputBits)

				inputLabels := make([]uint128.Uint128, 2*numInputs)
				outputLabels := make([]uint128.Uint128, 2*numOutputs)
				gc := NewGarbledCircuit(numInputs, numOutputs, garbleType, nil)
				gc.StartBuilding()

				inputWires := make([]int, numInputs)
				for i := 0; i < len(inputWires); i++ {
					inputWires[i] = i
				}
				outputWires := make([]int, numOutputs)

				gc.CircuitAND(inputWires, outputWires)
				gc.FinishBuilding(outputWires)

				err := gc.Garble(nil, outputLabels)
				if err != nil {
					b.Fatalf("gc.Garble failed: %v", err)
				}
				for i := 0; i < numInputs; i++ {
					inputLabels[2*i] = gc.Wires[2*i]
					inputLabels[2*i+1] = gc.Wires[2*i+1]
				}

				computedOutputLabels := make([]uint128.Uint128, numOutputs)
				outputBits := make([]bool, numOutputs)
				extractedLabels := ExtractLabels(inputLabels, inputBits)

				for b.Loop() {
					err = gc.Eval(extractedLabels, computedOutputLabels, outputBits)
					if err != nil {
						b.Fatalf("gc.Eval failed: %v", err)
					}
					if outputBits[0] != expected {
						b.Fatalf("expected output of %t, but got %t", expected, outputBits[0])
					}
				}
			})
		}
	}
}
