package main

import (
	"math/big"
)

// A function that implements (textbook) RSA to generate RSA parameters
func txtBookRSA(bitSize int) (*big.Int, *big.Int, *big.Int) { // Returns e, d, N of type big.Int

	e := big.NewInt(65537) // Common choice for e

	// Generate p, q
	p := genPrime(bitSize / 2)
	q := genPrime(bitSize / 2)

	// Calculate N = p*q
	N := new(big.Int).Mul(p, q)

	// Calculate phi = (p-1)*(q-1)
	pMinus1 := new(big.Int).Sub(p, big.NewInt(1))
	qMinus1 := new(big.Int).Sub(q, big.NewInt(1))
	phi := new(big.Int).Mul(pMinus1, qMinus1)

	// Calculate d the modular inverse of e mod phi
	d := new(big.Int).ModInverse(e, phi)

	return e, d, N // (e, N) public parameters

}

// Encryption/Decryption using the textbook RSA we defined earlier
// Function that encryptes messages using the public key (e, N)
func Encrypt(message []byte, e, N *big.Int) *big.Int {
	m := new(big.Int).SetBytes(message)
	c := new(big.Int).Exp(m, e, N) // c = m^e mod N
	return c
}

// Function that decryptes messages using the private key (d, N)
func Decrypt(c, d, N *big.Int) string {
	m := new(big.Int).Exp(c, d, N) // m = c^d mod N

	// Convert the decrypted message from bytes to string
	return string(m.Bytes())
}

