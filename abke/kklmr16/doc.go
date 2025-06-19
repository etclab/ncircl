// Package kklmr16 implements the Attribute-Based Key Exchange (ABKE) scheme
// from the [paper]:
//
//	@inproceedings{16-ccs-abke,
//	    title = {Attribute-based Key Exchange with General Policies},
//	    author = {Vladimir Kolesnikov and Hugo Krawczyk and Yehuda Lindell and Alex J. Malozemoff and Tal Rabin},
//	    booktitle = {ACM Conference on Computer and Communications Security (CCS)},
//	    year = {2016},
//	}
//
// Specifically, this package implements the scheme in section 9 of that paper
// (ASE using ELH Signatures), and is a port of Alex J. Malozemoff's  original
// [C code].
//
// [paper]: https://eprint.iacr.org/2016/518.pdf
// [C code]: https://github.com/amaloz/abke
package kklmr16
