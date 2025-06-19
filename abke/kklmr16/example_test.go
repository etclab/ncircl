package kklmr16_test

import (
	"fmt"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/etclab/ncircl/abke/kklmr16"
	"github.com/etclab/ncircl/util/blspairing"
)

func Example() {
	pp := kklmr16.NewPublicParams(4)
	ca := kklmr16.NewCertificateAuthority(pp)

	attrs := []bool{true, false, false, true}
	pk, sk := ca.GenCert(attrs)

	// generate random plaintext
	pt := make([]*bls.G1, pp.NumAttrs*2)
	for i := 0; i < len(pt); i++ {
		pt[i] = blspairing.NewRandomG1()
	}

	ct := kklmr16.Encrypt(pp, pk, attrs, pt)
	got := kklmr16.Decrypt(pp, sk, attrs, ct)

	fmt.Printf("%v %v %v %v\n",
		got[0].IsEqual(pt[1]),
		got[1].IsEqual(pt[2]),
		got[2].IsEqual(pt[4]),
		got[3].IsEqual(pt[7]))
	// Output:
	// true true true true
}
