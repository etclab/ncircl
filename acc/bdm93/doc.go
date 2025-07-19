// Package bdm93 implements the original RSA-based cryptographic accumulator
// from the [paper]:
//
//	@inproceedings{93-eurocrypt-one_way_accumulators,
//	  title = {One-way Accumulators: {A} Decentralized Alternative to Digital Signatures},
//	  author = {Benaloh, Josh and de Mare, Michael},
//	  booktitle = {International Conference on the Theory and Applications of Cryptographic Techniques (EUROCRYPT)},
//	  year = {1993},
//	}
//
// Specifically, the paper implements an accumulator in the trusted accumulator
// manager setting, and supports both adding and deleting elements from the
// accumulator.  The package also implements the witness aggregation and proof
// of exponentiation (PoE) from the [BBF19] paper:
//
//	@inproceedings{19-crypto-batching_for_accumulators,
//	  title = {Batching Techniques for Accumulators with Applications to {IOPs} and Stateless Blockchains},
//	  author = {Boneh, Dan and B\"{u}nz, Benedikt and Fisch, Ben},
//	  booktitle = {International Cryptology Conference (CRYPTO)}
//	  year = {2019},
//	}
//
// [paper]: https://link.springer.com/content/pdf/10.1007/3-540-48285-7_24.pdf
// [BBF19]: https://eprint.iacr.org/2018/1188.pdf
package bdm93
