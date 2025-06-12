// Package elgamal implements the ElGamal encryption scheme from the [paper]:
//
//	@article{85-toit-elgamal,
//	    title={A Public Key Cryptosystem and a Signature Scheme Based on Discrete Logarithms},
//	    journal = {IEEE Transactions on Information Theory},
//	    author = {ElGamal, Taher},
//	    year={1985},
//	    month = jul,
//	    volume={31},
//	    number={4},
//	}
//
// Properties:
// - Security is based on the decisional Diffie Hellman assumption
// - Semantically secure (IND-CPA)
// - Encryption is malleable
//
// [paper]: https://people.csail.mit.edu/alinush/6.857-spring-2015/papers/elgamal.pdf
package elgamal
