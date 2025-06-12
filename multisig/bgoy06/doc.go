// Package bgoy06 implements the ordered multisignature (OMS) scheme from:
//
//	Alexandra Boldyreva, Craig Gentry, Adam O'Neill, Dae Hyun Yum.
//	"Ordered Multisignatures and Identity-Based Sequential Aggregate Signatures with Applications to Secure Routing."
//	In ACM Conference on Computer and Communications Security (CCS), 2006.
//
// Section 3 of that [paper] describes the scheme.
//
// Note that the paper assumes a symmetric pairing.  To convert the scheme to
// use BLS (an asymmetric pairing), we modify the algorithms slightly:
//
// # KeyGen
//
// Private Key:
//
//	s \stackrel{\$}{\leftarrow} \mathbb{Z}_p
//	t \stackrel{\$}{\leftarrow} \mathbb{Z}_p
//	u \stackrel{\$}{\leftarrow} \mathbb{Z}_p
//	sk = (s, t, u)
//
// Public Key:
//
//	S \leftarrow g_2^s  (in \mathbb{G}_2)
//	T \leftarrow g_1^t  (in \mathbb{G}_1)
//	U \leftarrow g_1^u  (in \mathbb{G}_1)
//	pk = (S, T, U)
//
// # Sign
//
//	R' \leftarrow R \cdot g^r  (\in \mathbb{G}_2)
//	X' \leftarrow (R')^{t_i + iu_i} \cdot X (\in \mathbb{G}_2)
//	Y' \leftarrow (\prod_{j=1}^{i-1} T_j \codt U_j^j)^r \cdot Y' (\in \mathbb{G}_1)
//	Q' \leftarrow H(m)^{s_i} \cdot Q (\in \mathbb{G}_1)
//
// The signature is:
//
//	(Q', X', Y', R')
//
// # Verify
//
//	e(Q,g_2) \cdot e(g_1, Y) \cdot e(g_1, X) \stackrel{?}{=} e(H(m), \prod_{i=1}{n}S_i) \cdot e(\prod_{i=1}{n}T_i(U_i)^i, R)
//
// Note the following differences between the symmetric and asymmetric
// versions:
//
//	                        Symmetric           Asymmetric
//	                        --------            ----------
//	Signature Size          2 group elements     4 elements (2 in \mathbb{G}_1, 2 in \mathbb{G}_2)
//	Pairing Ops in Verify   3                   5
//
// [paper]: https://eprint.iacr.org/2007/438.pdf
package bgoy06
