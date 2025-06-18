// Package bhkr implements the garbled circuit scheme from the [paper]:
//
//	@inproceedings{13-oakland-efficient_garbling,
//	    title = {Efficient Garbling from a Fixed-Key Blockcipher},
//	    author = {Bellare, Mihir, and Hoang, Viet Tung and Keelveedhi, Sriram and Rogaway, Phillip},
//	    booktitle = {IEEE Symposium on Security and Privacy},
//	    year = {2013},
//	}
//
// The original implementation of this scheme is UCSD's [JustGarble]. Alex
// Malozemoff also implements the scheme in [libgarble].
//
// [paper]: https://eprint.iacr.org/2013/426.pdf
// [JustGarble]: https://cseweb.ucsd.edu//groups/justgarble/
// [libgarble]: https://github.com/amaloz/libgarble
package bhkr13
