// Package lv08 implements the proxy re-encryption scheme from the [paper]:
//
// Specifically, the package implements the scheme from section 3.1 of that
// paper.
//
//	@inproceedings{08-pkc-cca_proxy_reencryption,
//	    title = {Unidirectional Chosen-Ciphertext Secure Proxy Re-Encryption},
//	    author = {Libert, Benoît and Vergnaud, Damien},
//	    booktitle = {International Workshop on Public Key Cryptography (PKC)},
//	    year = {2008},
//	}
//
// # Changes from Paper
// The paper assumes a symmetric pairing.  In order to support the asymmetric
// pairing of BLS12-381, this package changes the public key so that instead of
// being the single element g^x, it is the two elements g1^x and g2^x, where g1
// is the generator for G1 and g2 is the generator for G2.
//
// # Properties:
// - Unidirectional
// - Single-hop
// - Chosen-ciphertext security in the standard model
//
// [paper]: https://www.iacr.org/archive/pkc2008/49390363/49390363.pdf
package lv08
