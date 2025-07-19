package bdm93

import (
	"math/big"
	"testing"

	"github.com/etclab/ncircl/util/bytesx"
)

var (
	itemSize   = 1024
	rsaBitSize = 3096
)

func TestAccumulatorManager_Add(t *testing.T) {
	mgr := NewAccumulatorManager(rsaBitSize)
	w := mgr.Add(bytesx.Random(itemSize))
	valid := mgr.VerifyWitness(w)
	if !valid {
		t.Fatalf("expected VerifyWitness to return true, but got %v", valid)
	}
}

func TestStaleWitness(t *testing.T) {
	mgr := NewAccumulatorManager(rsaBitSize)
	w1 := mgr.Add(bytesx.Random(itemSize))
	w2 := mgr.Add(bytesx.Random(itemSize))

	valid := mgr.VerifyWitness(w2)
	if !valid {
		t.Fatalf("expected VerifyWitness to return true, but got %v", valid)
	}

	// w1's witness is stale and needs to be updated
	valid = mgr.VerifyWitness(w1)
	if valid {
		t.Fatalf("expected VerifyWitness on a stale witness to return false, but got %v", valid)
	}
}

func TestWitness_Update(t *testing.T) {
	mgr := NewAccumulatorManager(rsaBitSize)
	w1 := mgr.Add(bytesx.Random(itemSize))
	w2 := mgr.Add(bytesx.Random(itemSize))

	valid := mgr.VerifyWitness(w2)
	if !valid {
		t.Fatalf("expected VerifyWitness to return true, but got %v", valid)
	}

	w1.Update(w2.X)

	// w1's witness is stale and needs to be updated
	valid = mgr.VerifyWitness(w1)
	if !valid {
		t.Fatalf("expected VerifyWitness on a updated witness to return true, but got %v", valid)
	}
}

func TestShamirTrick(t *testing.T) {
	mgr := NewAccumulatorManager(rsaBitSize)

	w1 := mgr.Add(bytesx.Random(itemSize))
	w2 := mgr.Add(bytesx.Random(itemSize))
	w1.Update(w2.X)

	w12, err := ShamirTrick(w1, w2)
	if err != nil {
		t.Fatalf("ShamirTrick failed: %v", err)
	}

	valid := mgr.VerifyWitness(w12)
	if !valid {
		t.Fatalf("expected VerifyWitness on a aggregated witness to return true, but got %v", valid)
	}
}

func TestAggregateWitnesses(t *testing.T) {
	mgr := NewAccumulatorManager(rsaBitSize)

	witnesses := make([]*Witness, 16)
	for i := 0; i < len(witnesses); i++ {
		w := mgr.Add(bytesx.Random(itemSize))
		for j := 0; j < i; j++ {
			witnesses[j].Update(w.X)
		}
		witnesses[i] = w
	}

	aggWit, err := AggregateWitnesses(witnesses[6:11])
	if err != nil {
		t.Fatalf("AggregateWitnesses failed: %v", err)
	}

	valid := mgr.VerifyWitness(aggWit)
	if !valid {
		t.Fatalf("expected VerifyWitness on a aggregated witness to return true, but got %v", valid)
	}
}

func TestVerifyNIPoE(t *testing.T) {
	mgr := NewAccumulatorManager(rsaBitSize)

	w := mgr.Add(bytesx.Random(itemSize))
	valid := mgr.VerifyWitness(w)
	if !valid {
		t.Fatalf("expected VerifyWitness to return true, but got %v", valid)
	}

	proof := NIPoE(w)

	valid = VerifyNIPoE(mgr.AccValue, w, proof)
	if !valid {
		t.Fatalf("expected VerifyNIPoE to return true, but got %v", valid)
	}
}

func BenchmarkHashToPrime(b *testing.B) {
	data := bytesx.Random(itemSize)
	for b.Loop() {
		HashToPrime(data)
	}
}

func BenchmarkAccumulatorManager_Add(b *testing.B) {
	mgr := NewAccumulatorManager(rsaBitSize)
	for b.Loop() {
		b.StopTimer()
		item := bytesx.Random(itemSize)
		b.StartTimer()
		mgr.Add(item)
	}
}

func BenchmarkAccumulatorManager_Remove(b *testing.B) {
	mgr := NewAccumulatorManager(rsaBitSize)
	item := bytesx.Random(itemSize)
	for b.Loop() {
		b.StopTimer()
		mgr.Add(item)
		b.StartTimer()
		mgr.Remove(item)
	}
}

func BenchmarkWitness_VerifyWitness(b *testing.B) {
	mgr := NewAccumulatorManager(rsaBitSize)
	w := mgr.Add(bytesx.Random(itemSize))
	for b.Loop() {
		valid := mgr.VerifyWitness(w)
		if !valid {
			b.Fatalf("expected VerifyWitness to return true, but got %v", valid)
		}
	}
}

// Note that even though the Update and Verify are both just exponentiations,
// the Remove exponent is far larger than the Add exponent.
func BenchmarkWitness_Update(b *testing.B) {
	var upd *big.Int
	mgr := NewAccumulatorManager(rsaBitSize)
	w1 := mgr.Add(bytesx.Random(itemSize))
	w2Item := bytesx.Random(itemSize)
	i := 0
	for b.Loop() {
		b.StopTimer()
		if i%2 == 0 {
			w2 := mgr.Add(w2Item)
			upd = w2.X
		} else {
			upd = mgr.Remove(w2Item)
		}
		i += 1
		b.StartTimer()

		w1.Update(upd)
	}
}
