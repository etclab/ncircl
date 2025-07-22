package bdm93

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"math/big"

	"github.com/etclab/mu"
)

var (
	bigOne = big.NewInt(1)
	bigTwo = big.NewInt(2)

	ErrShamirTrick = errors.New("bdm93: ShamirTrick: invalid inputs")
)

func bigIntClone(x *big.Int) *big.Int {
	return new(big.Int).Set(x)
}

func HashToPrime(data []byte) *big.Int {
	h := sha256.Sum256(data)
	x := new(big.Int).SetBytes(h[:])
	// make sure x is odd
	if x.Bit(0) == 0 {
		x.Add(x, bigOne)
	}

	// Keep looping until find an odd prime
	//
	// With an input of 10, ProbablyPrime has only ~0.0001% chance of a false
	// positive (saying that a non-prime is prime).  If x is prime,
	// ProbablyPrime always returns true.
	for !x.ProbablyPrime(10) || x.Cmp(bigTwo) == 0 {
		h := sha256.Sum256(x.Bytes())
		x.SetBytes(h[:])
		// make sure x is odd
		if x.Bit(0) == 0 {
			x.Add(x, bigOne)
		}
	}
	return x
}

type AccumulatorManager struct {
	SK       *rsa.PrivateKey
	Totient  *big.Int // Totient = (P-1)*(Q-1)
	AccValue *big.Int
}

func NewAccumulatorManager(rsaKeyBits int) *AccumulatorManager {
	var err error
	mgr := new(AccumulatorManager)
	mgr.SK, err = rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		mu.BUG("rsa.GenerateKey failed: %v", err)
	}

	p := mgr.SK.Primes[0]
	q := mgr.SK.Primes[1]

	pminus1 := new(big.Int).Sub(p, bigOne)
	qminus1 := new(big.Int).Sub(q, bigOne)
	mgr.Totient = new(big.Int).Mul(pminus1, qminus1)

	mgr.AccValue = big.NewInt(65537) // g (base)

	return mgr
}

type Witness struct {
	X *big.Int
	A *big.Int
	N *big.Int
}

func (w *Witness) Clone() *Witness {
	return &Witness{
		X: bigIntClone(w.X),
		A: bigIntClone(w.A),
		N: bigIntClone(w.N),
	}
}

// Add adds an item to the accumulator.  It returns the witness for the
// item added, and the update value for updating the witnesses for
// any existing items in the accumulator.
func (mgr *AccumulatorManager) Add(item []byte) (*Witness, *big.Int) {
	prime := HashToPrime(item)
	w := new(Witness)
	w.A = bigIntClone(mgr.AccValue)
	w.N = mgr.SK.N

	// raise accumulator to the exponent; take value mod N
	x := new(big.Int)
	x.Mod(prime, mgr.Totient)
	w.X = x
	mgr.AccValue.Exp(mgr.AccValue, x, mgr.SK.N)

	return w, w.X
}

// Remove removes an item from the accumulator.  It returns the update value
// for updating the witnesses for any remaining itmes in the accumulator.
func (mgr *AccumulatorManager) Remove(item []byte) *big.Int {
	prime := HashToPrime(item)
	x := new(big.Int)
	x.Mod(prime, mgr.Totient)
	xInv := new(big.Int).ModInverse(x, mgr.Totient)
	mgr.AccValue.Exp(mgr.AccValue, xInv, mgr.SK.N)
	return xInv
}

// VerifyWitness verifies a witness against the current accumulator value.
func (mgr *AccumulatorManager) VerifyWitness(w *Witness) bool {
	//x := new(big.Int)
	//x.Mod(w.Prime, mgr.Totient)
	v := new(big.Int).Exp(w.A, w.X, mgr.SK.N)
	return mgr.AccValue.Cmp(v) == 0
}

// Update updates a witness.  Witnesses need to be updated any time
// an item is addded or removed from the accumulator.
func (w *Witness) Update(update *big.Int) {
	w.A.Exp(w.A, update, w.N)
}

// shamirTrick is a trick that computes w^{xy} from w1^x,w2^y.
// In the context of accumulators, it aggregates two witnesses into a single
// witness for both values.
func shamirTrick(w1, w2 *Witness) (*Witness, error) {
	w1tox := new(big.Int).Exp(w1.A, w1.X, w1.N)
	w2toy := new(big.Int).Exp(w2.A, w2.X, w2.N)
	if w1tox.Cmp(w2toy) != 0 {
		return nil, ErrShamirTrick
	}

	one := new(big.Int)
	a := new(big.Int)
	b := new(big.Int)
	one.GCD(a, b, w1.X, w2.X)
	one.Mod(one, w1.N)

	if one.Cmp(bigOne) != 0 {
		mu.BUG("ShamirTrick: x and y are not coprime")
	}

	w1tob := new(big.Int).Exp(w1.A, b, w1.N)
	w2toa := new(big.Int).Exp(w2.A, a, w2.N)

	prod := new(big.Int).Mul(w1tob, w2toa)
	prod.Mod(prod, w1.N)

	xy := new(big.Int).Mul(w1.X, w2.X)

	aggWit := Witness{
		X: xy,
		A: prod,
		N: bigIntClone(w1.N),
	}

	return &aggWit, nil
}

// AggregateWitnesses aggregates a list of witnesses into a single witness
// for all of their respective values.
func AggregateWitnesses(witnesses []*Witness) (*Witness, error) {
	var err error
	agg := witnesses[0].Clone()
	for _, w := range witnesses[1:] {
		agg, err = shamirTrick(agg, w)
		if err != nil {
			return nil, err
		}
	}
	return agg, nil
}

type PoE struct {
	Prime *big.Int
	Q     *big.Int
}

func NIPoE(w *Witness) *PoE {
	p, err := rand.Prime(rand.Reader, 256)
	if err != nil {
		mu.Panicf("rand.Prime failed: %v", err)
	}

	h := sha256.Sum256(p.Bytes())
	bigH := new(big.Int).SetBytes(h[:])

	q := new(big.Int).Div(w.X, bigH)
	Q := new(big.Int).Exp(w.A, q, w.N)

	return &PoE{
		Q:     Q,
		Prime: p,
	}
}

func VerifyNIPoE(accValue *big.Int, w *Witness, proof *PoE) bool {
	h := sha256.Sum256(proof.Prime.Bytes())
	bigH := new(big.Int).SetBytes(h[:])

	r := new(big.Int).Mod(w.X, bigH)
	a := new(big.Int).Exp(proof.Q, bigH, w.N)
	b := new(big.Int).Exp(w.A, r, w.N)
	got := new(big.Int).Mul(a, b)
	got.Mod(got, w.N)

	return accValue.Cmp(got) == 0
}
