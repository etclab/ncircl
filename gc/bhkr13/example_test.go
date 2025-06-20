package bhkr13_test

import (
	"fmt"
	"log"

	"github.com/etclab/ncircl/gc/bhkr13"
	"github.com/etclab/ncircl/util/uint128"
)

// build a simple AND policy (abke/src/policies.c)

func Example() {
	numInputs := 2
	numOutputs := 1
	numGates := 1

	inputLabels := make([]uint128.Uint128, 2*numInputs)
	outputLabels := make([]uint128.Uint128, 2*numOutputs)

	gc := bhkr13.NewGarbledCircuit(numInputs, numOutputs, nil)
	delta := gc.CreateDelta()
	gc.CreateInputLabels(inputLabels, delta)

	inputs := make([]int, numInputs)
	for i := 0; i < len(inputs); i++ {
		inputs[i] = i
	}
	outputs := make([]int, numOutputs)

	gc.StartBuilding()
	gc.CircuitAND(inputs, outputs)
	for i := numInputs; i <= numGates; i++ {
		wire2 := gc.NextWire()
		gc.GateAND(outputs[0], outputs[0], wire2)
		outputs[0] = wire2
	}

	gc.FinishBuilding(outputs)

	err := gc.Garble(inputLabels, outputLabels)
	if err != nil {
		log.Fatalf("gc.Garble failed: %v", err)
	}

	fmt.Println("here")
	// Output:
	// here
}
