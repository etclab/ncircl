// Package bf01 implements the identity-based encryption scheme from the
// [paper]:
//
//	@inproceedings{01-crypto-ibe_weil_pairing,
//	    title = {Identity-Based Encryption from the {Weil} Pairing},
//	    author = {Boneh, Dan and Franklin, Matthew K.},
//	    booktitle = {International Cryptology Conference (CRYPTO)},
//	    year = {2001},
//	}
//
// Section 4 of that paper describes the scheme.  Alin Tomescu's blog
// [article] on pairings also provides a clear and concise description.
//
// [paper]: https://eprint.iacr.org/2001/090.pdf
// [article]: https://alinush.github.io/pairings
package bf01
