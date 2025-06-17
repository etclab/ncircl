// Package ch07 implements the proxy re-encryption (PRE) scheme from the
// [paper]:
//
//	@inproceedings{07-ccs-cca_proxy_re_encryption,
//	    title = {Chosen-ciphertext Secure Proxy Re-encryption},
//	    author = {Canetti, Ran and Hohenberger, Susan},
//	    booktitle = {ACM Conference on Computer and Communications Security (CCS)},
//	    year = {2007},
//	}
//
// This package specifically implements the PRE scheme in the Random Oracle
// Model from Section 3.2 of that paper.
//
// Properties:
// - CCA-secure
// - bidirectional (a re-encryption key from Alice to Bob also permits
// re-encryptino from Bob to Alice)
//   - multihop (a ciphertext may be re-encrypted multiple times---from Alice to Bob
//     to Carol, etc.)
//
// [paper]: https://eprint.iacr.org/2007/171.pdf
package ch07
