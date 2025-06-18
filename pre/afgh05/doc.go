// The afgh05 package implements the proxy re-encryption scheme from the
// [paper]:
//
//	 @inproceedings{05-ndss-improved_proxy_reencryption,
//	     title = {Improved Proxy Re-Encryption Schemes with Applications to Secure Distributed Storage},
//	     author = {Ateniese, Giuseppe and Fu, Kevin and Green, Matthew and Hohenberger, Susan},
//		    booktitle = {Network and Distributed System Security Symposium (NDSS)},
//	     year = {2005},
//	 }
//
// Section 3.1 of the [paper] describes the scheme.  Note that this package
// implements the "Second Attempt", not the final "Third Attempt."  The
// [lecture notes] from Susan Hohenberger and Matthew Green also describe the
// "Second Attempt" in a concise manner.
//
// This scheme is:
//   - unidirectional (a re-encryption key from Alice to Bob does not permit
//     re-encryption from Bob to Alice)
//   - single-hop (once re-encrypted, a ciphertext cannot again be re-encrypted)
//   - CPA-secure (aka, semantically secure)
//
// [paper]: https://www.ndss-symposium.org/wp-content/uploads/2017/09/Improved-Proxy-Re-Encryption-Schemes-with-Applications-to-Secure-Distributed-Storage-Kevin-Fu.pdf
// [lecture notes]: https://www.cs.jhu.edu/~susan/600.641/scribes/lecture17.pdf
package afgh05
