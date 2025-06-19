// Package lv08 implements the proxy re-encryption scheme from the [paper]:
//
// Specifically, the package implements the scheme from section 3.1 of that
// paper.
// 
//  @inproceedings{08-pkc-cca_proxy_reencryption,
//      title = {Unidirectional Chosen-Ciphertext Secure Proxy Re-Encryption},
//      author = {Libert, Benoît and Vergnaud, Damien},
//      booktitle = {International Workshop on Public Key Cryptography (PKC)},
//      year = {2008},
//  }
//
// Properties:
// - Unidirectional
// - Single-hop
// - Chosen-ciphertext security in the standard model
//
// [paper]: https://www.iacr.org/archive/pkc2008/49390363/49390363.pdf
package lv08
