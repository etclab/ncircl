package bdm93

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"testing"

	"github.com/etclab/ncircl/util/bytesx"
)

var (
	defaultItemSize     = 1024
	defaultRSABitSize   = 3096
	defaultNumWitnesses = 128
)

func TestHashtoPrime(t *testing.T) {
	preImage := bytesx.Random(defaultItemSize)

	x := HashToPrime(preImage)
	if !x.ProbablyPrime(10) {
		t.Error("HashToPrime returned a non-prime number")
	}
	if x.Cmp(bigTwo) == 0 {
		t.Error("HashToPrime returned an even prime (2)")
	}

	y := HashToPrime(preImage)
	if !y.ProbablyPrime(10) {
		t.Error("HashToPrime returned a non-prime number")
	}
	if !y.ProbablyPrime(10) {
		t.Error("HashToPrime returned a non-prime number")
	}
	if y.Cmp(bigTwo) == 0 {
		t.Error("HashToPrime returned an even prime (2)")
	}

	if x.Cmp(y) != 0 {
		t.Error("HashToPrime returned different primes for the same pre-image")
	}
}

func TestAccumulatorManager_Add(t *testing.T) {
	mgr := NewAccumulatorManager(defaultRSABitSize)
	w, _ := mgr.Add(bytesx.Random(defaultItemSize))
	valid := mgr.VerifyWitness(w)
	if !valid {
		t.Fatalf("expected VerifyWitness to return true, but got %v", valid)
	}
}

func TestStaleWitness(t *testing.T) {
	mgr := NewAccumulatorManager(defaultRSABitSize)
	w1, _ := mgr.Add(bytesx.Random(defaultItemSize))
	w2, _ := mgr.Add(bytesx.Random(defaultItemSize))

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
	mgr := NewAccumulatorManager(defaultRSABitSize)
	w1, _ := mgr.Add(bytesx.Random(defaultItemSize))
	w2, upd2 := mgr.Add(bytesx.Random(defaultItemSize))

	valid := mgr.VerifyWitness(w2)
	if !valid {
		t.Fatalf("expected VerifyWitness to return true, but got %v", valid)
	}

	w1.Update(upd2)

	// w1's witness is stale and needs to be updated
	valid = mgr.VerifyWitness(w1)
	if !valid {
		t.Fatalf("expected VerifyWitness on a updated witness to return true, but got %v", valid)
	}
}

func Test_shamirTrick(t *testing.T) {
	mgr := NewAccumulatorManager(defaultRSABitSize)

	w1, _ := mgr.Add(bytesx.Random(defaultItemSize))
	w2, upd2 := mgr.Add(bytesx.Random(defaultItemSize))
	w1.Update(upd2)

	w12, err := shamirTrick(w1, w2)
	if err != nil {
		t.Fatalf("ShamirTrick failed: %v", err)
	}

	valid := mgr.VerifyWitness(w12)
	if !valid {
		t.Fatalf("expected VerifyWitness on a aggregated witness to return true, but got %v", valid)
	}
}

func TestAggregateWitnesses(t *testing.T) {
	mgr := NewAccumulatorManager(defaultRSABitSize)

	witnesses := make([]*Witness, 16)
	for i := 0; i < len(witnesses); i++ {
		w, upd := mgr.Add(bytesx.Random(defaultItemSize))
		for j := 0; j < i; j++ {
			witnesses[j].Update(upd)
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
	mgr := NewAccumulatorManager(defaultRSABitSize)

	w, _ := mgr.Add(bytesx.Random(defaultItemSize))
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
	data := bytesx.Random(defaultItemSize)
	for b.Loop() {
		HashToPrime(data)
	}
}

func BenchmarkAccumulatorManager_Add(b *testing.B) {
	mgr := NewAccumulatorManager(defaultRSABitSize)
	for b.Loop() {
		b.StopTimer()
		item := bytesx.Random(defaultItemSize)
		b.StartTimer()
		mgr.Add(item)
	}
}

func BenchmarkAccumulatorManager_Remove(b *testing.B) {
	mgr := NewAccumulatorManager(defaultRSABitSize)
	item := bytesx.Random(defaultItemSize)
	for b.Loop() {
		b.StopTimer()
		mgr.Add(item)
		b.StartTimer()
		mgr.Remove(item)
	}
}

func BenchmarkWitness_VerifyWitness(b *testing.B) {
	mgr := NewAccumulatorManager(defaultRSABitSize)

	witnesses := make([]*Witness, defaultNumWitnesses)
	for i := 0; i < len(witnesses); i++ {
		w, upd := mgr.Add(bytesx.Random(defaultItemSize))
		for j := 0; j < i; j++ {
			witnesses[j].Update(upd)
		}
		witnesses[i] = w
	}

	for n := 1; n <= defaultNumWitnesses; n *= 2 {
		b.Run(fmt.Sprintf("numAggregatedWitnesses:%d", n), func(b *testing.B) {
			var w *Witness
			var err error
			if n > 1 {
				w, err = AggregateWitnesses(witnesses[:n])
				if err != nil {
					b.Fatalf("AggregateWitnesses failed: %v", err)
				}
			} else {
				w = witnesses[0]
			}

			for b.Loop() {
				valid := mgr.VerifyWitness(w)
				if !valid {
					b.Fatal("witness failed verification")
				}
			}
		})
	}
}

// Note that even though the Update and Verify are both just exponentiations,
// the Remove exponent is far larger than the Add exponent.
func BenchmarkWitness_Update(b *testing.B) {
	var upd *big.Int

	mgr := NewAccumulatorManager(defaultRSABitSize)
	w1, _ := mgr.Add(bytesx.Random(defaultItemSize))
	item2 := bytesx.Random(defaultItemSize)

	i := 0
	for b.Loop() {
		b.StopTimer()
		if i%2 == 0 {
			_, upd = mgr.Add(item2)
		} else {
			upd = mgr.Remove(item2)
		}
		i += 1
		b.StartTimer()

		w1.Update(upd)
	}
}

func BenchmarkAggregateWitnesses(b *testing.B) {
	mgr := NewAccumulatorManager(defaultRSABitSize)

	witnesses := make([]*Witness, defaultNumWitnesses)
	for i := 0; i < len(witnesses); i++ {
		w, upd := mgr.Add(bytesx.Random(defaultItemSize))
		for j := 0; j < i; j++ {
			witnesses[j].Update(upd)
		}
		witnesses[i] = w
	}

	for n := 2; n <= defaultNumWitnesses; n *= 2 {
		b.Run(fmt.Sprintf("numWitnesses:%d", n), func(b *testing.B) {
			for b.Loop() {
				_, err := AggregateWitnesses(witnesses[:n])
				if err != nil {
					b.Fatalf("AggregateWitnesses failed: %v", err)
				}
			}
		})
	}
}

func BenchmarkNIPoE(b *testing.B) {
	mgr := NewAccumulatorManager(defaultRSABitSize)

	witnesses := make([]*Witness, defaultNumWitnesses)
	for i := 0; i < len(witnesses); i++ {
		w, upd := mgr.Add(bytesx.Random(defaultItemSize))
		for j := 0; j < i; j++ {
			witnesses[j].Update(upd)
		}
		witnesses[i] = w
	}

	for n := 1; n <= defaultNumWitnesses; n *= 2 {
		b.Run(fmt.Sprintf("numAggregatedWitnesses:%d", n), func(b *testing.B) {
			var w *Witness
			var err error
			if n > 1 {
				w, err = AggregateWitnesses(witnesses[:n])
				if err != nil {
					b.Fatalf("AggregateWitnesses failed: %v", err)
				}
			} else {
				w = witnesses[0]
			}

			for b.Loop() {
				_ = NIPoE(w)
			}
		})
	}
}

func BenchmarkVerifyNIPoE(b *testing.B) {
	mgr := NewAccumulatorManager(defaultRSABitSize)

	witnesses := make([]*Witness, defaultNumWitnesses)
	for i := 0; i < len(witnesses); i++ {
		w, upd := mgr.Add(bytesx.Random(defaultItemSize))
		for j := 0; j < i; j++ {
			witnesses[j].Update(upd)
		}
		witnesses[i] = w
	}

	for n := 1; n <= defaultNumWitnesses; n *= 2 {
		b.Run(fmt.Sprintf("numAggregatedWitnesses:%d", n), func(b *testing.B) {
			var w *Witness
			var err error
			if n > 1 {
				w, err = AggregateWitnesses(witnesses[:n])
				if err != nil {
					b.Fatalf("AggregateWitnesses failed: %v", err)
				}
			} else {
				w = witnesses[0]
			}

			proof := NIPoE(w)

			for b.Loop() {
				valid := VerifyNIPoE(mgr.AccValue, w, proof)
				if !valid {
					b.Fatal("VerifyNIPoE returned false")
				}
			}
		})
	}
}

func BenchmarkSHA256Baseline(b *testing.B) {
	// This benchmark simply provides a relative baseline for comparing the
	// performance of the accumulator against a traditional hash function.
	preImage := bytesx.Random(defaultItemSize)
	for b.Loop() {
		_ = sha256.Sum256(preImage)
	}
}
