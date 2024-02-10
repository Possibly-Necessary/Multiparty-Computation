package main

import (

	crand "crypto/rand" // using alias
	//"encoding/binary"
	"math/big"
	"math/rand"

	"time"

)

var smallPrimes = []int64{2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
	31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
	73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
	127, 131, 137, 139, 149, 151, 157, 163, 167, 173,
	179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
}

// _______________________________ Primality Testing & Prime Numbers ______________________
// randBigIntRange generates a random big.Int in the range [min, max].
func randBigIntRange(min, max *big.Int) *big.Int {
	// Calculate the range delta = max - min + 1
	delta := new(big.Int).Sub(max, min)
	delta = delta.Add(delta, big.NewInt(1)) 

	// Generate a random number in [0, delta)
	randNum, err := crand.Int(crand.Reader, delta)
	if err != nil {
		panic(err) 
	}

	// Shift the random number into the range [min, max]
	randNum = randNum.Add(randNum, min)
	return randNum
}

// Rabin-Miller primality test
func RabinMiller(n *big.Int, k int) bool {

	if n.Cmp(big.NewInt(2)) == 0 { // Check if n == 2
		return true
	}

	if new(big.Int).Mod(n, big.NewInt(2)).Cmp(big.NewInt(0)) == 0 {
		return false
	}

	// Decompose n-1 into 2^(r*s) - r and s will represent the decomposition of n-1 into 2^(r*s)
	s := new(big.Int).Sub(n, big.NewInt(1)) // Subtract 1 from n and storing it in s
	r := 0
	if new(big.Int).Mod(n, big.NewInt(2)).Cmp(big.NewInt(0)) == 0 {
		s.Rsh(s, 1) // s = s/2
		r++
	}
	// Seed the rng
	rand.Seed(time.Now().UnixNano())

	// Run the Rabin-Miller
	for i := 0; i < k; i++ { // Generate random big.Int a in the range [2, n-2]
		a := randBigIntRange(big.NewInt(2), new(big.Int).Sub(n, big.NewInt(2)))
		x := new(big.Int).Exp(a, s, n) // Compute x = a^s mod n using big.Int's Exp method

		if x.Cmp(big.NewInt(1)) == 0 || x.Cmp(new(big.Int).Sub(n, big.NewInt(1))) == 0 {
			continue
		}

		xIsMinusOne := false
		for j := 0; j < r-1; j++ {
			x.Exp(x, big.NewInt(2), n)
			if x.Cmp(new(big.Int).Sub(n, big.NewInt(1))) == 0 {
				xIsMinusOne = true
				break
			}
		}

		if !xIsMinusOne {
			return false
		}
	}
	return true
}

func rabinMillerFast(n *big.Int, k int) bool {
	for _, p := range smallPrimes {
		// Convert p to *big.Int to use with big.Int methods
		prime := big.NewInt(int64(p))
		// Check if n is divisible by p
		if new(big.Int).Mod(n, prime).Cmp(big.NewInt(0)) == 0 {
			return false
		}
	}
	return RabinMiller(n, k)
}

func randBits(n int) *big.Int {
	// Calculate the maximum value for n bits
	max := new(big.Int).Lsh(big.NewInt(1), uint(n))
	// Generate a random big.Int in the range [0, max)
	randNum, err := crand.Int(crand.Reader, max)
	if err != nil {
		panic(err) 
	}
	return randNum
}

// Function that generates prime numbers of n bits
func genPrime(n int) *big.Int {
	rand.Seed(time.Now().UnixNano())

	// 1<<uint(n-1) Create a big.Int representing 2^(n-1)
	min := new(big.Int).Lsh(big.NewInt(1), uint(n-1))
	max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(n)), big.NewInt(1))

	for {
		p := randBigIntRange(min, max) // Generate a random odd number of bits
		p.Or(p, big.NewInt(1))     

		// Check divisibility by small primes
		div := false
		for _, smallPrime := range smallPrimes {
			if new(big.Int).Mod(p, big.NewInt(smallPrime)).Cmp(big.NewInt(0)) == 0 {
				div = true
				break
			}
		}
		if div {
			continue
		}
		if RabinMiller(p, 40) {
			return p
		}
	}
}
