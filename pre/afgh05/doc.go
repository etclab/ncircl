// The afgh05 package implements the proxy re-encryption scheme from:
//
//	Giuseppe Ateniese, Kevin Fu, Matthew Green, Susan Hohenberger.
//	"Improved Proxy Re-Encryption Schemes with Applications to Secure Distributed Storage."
//	In Network and Distributed System Security Symposium (NDSS), 2005
//
// Section 3.1 of the [paper] describes the scheme.  Note that this package
// implements the "Second Attempt", not the final "Third Attempt."  The
// [lecture notes] from Suan Hohenberger and Matthew Green also describe the
// "Second Attempt" in a concise manner.
//
// This scheme is:
//   - unidirectional (a re-encryption key from Alice to Bob does not permit
//     ren-encryption from Bob to Alice)
//   - single-hop (once re-encrypted, a ciphertext cannot again be re-encrypted)
//   - CPA-secure
//
// [paper]: https://www.ndss-symposium.org/wp-content/uploads/2017/09/Improved-Proxy-Re-Encryption-Schemes-with-Applications-to-Secure-Distributed-Storage-Kevin-Fu.pdf
// [lecture notes]: https://www.cs.jhu.edu/~susan/600.641/scribes/lecture17.pdf
package afgh05
