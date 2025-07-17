package bdm93

import (
	"crypto/rand"
	"crypto/rsa"
	"math/big"

	"github.com/etclab/mu"
	"golang.org/x/crypto/sha3"
)

var bigOne = big.NewInt(1)

func HashToPrime(data []byte) *big.Int {
	// Unclear if this is a good hash function.
	h := sha3.NewShake256()
	h.Write(data)
	p, err := rand.Prime(h, 256)
	if err != nil {
		mu.Panicf("rand.Prime failed: %v", err)
	}
	return p
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

func (mgr *AccumulatorManager) Add(item []byte) *Witness {
	prime := HashToPrime(item)
	w := new(Witness)
	w.A = new(big.Int).Set(mgr.AccValue) // clone the current AccValue
	w.N = mgr.SK.N

	// raise accumulator to the exponent; take value mod N
	x := new(big.Int)
	x.Mod(prime, mgr.Totient)
	w.X = x
	mgr.AccValue.Exp(mgr.AccValue, x, mgr.SK.N)

	return w
}

// returns the update for the other witness
func (mgr *AccumulatorManager) Remove(item []byte) *big.Int {
	prime := HashToPrime(item)
	x := new(big.Int)
	x.Mod(prime, mgr.Totient)
	xInv := new(big.Int).ModInverse(x, mgr.Totient)
	mgr.AccValue.Exp(mgr.AccValue, xInv, mgr.SK.N)
	return xInv
}

func (mgr *AccumulatorManager) VerifyWitness(w *Witness) bool {
	//x := new(big.Int)
	//x.Mod(w.Prime, mgr.Totient)
	v := new(big.Int).Exp(w.A, w.X, mgr.SK.N)
	return mgr.AccValue.Cmp(v) == 0
}

func (w *Witness) Update(update *big.Int) {
	w.A.Exp(w.A, update, w.N)
}
