package main

import (
	"fmt"
	"math/big"
	"math/rand"
	"sync"
	"time"
)

// _________________________ Oblivious Transfer____________________________
// Implementation of 1-2 Oblivious Transfer
// Oblivous transfer for Merlin's part -- using Go concurrency and channels
func ObliviousTransferMerlin(m0, m1, e, d, N *big.Int, ArthurChann, MerlinChann chan *big.Int, wg *sync.WaitGroup) {
	defer wg.Done()
	rand.Seed(time.Now().UnixNano())

	if e == nil || d == nil || N == nil {
		e, d, N = txtBookRSA(2048)
	}

	if m0.Cmp(N) >= 0 || m1.Cmp(N) >= 0 {
		// Send it Arthur (1)
	}

	// Generate x0, x1 as random large integers
	x0 := randBits(2048)
	x1 := randBits(2048)

	// Send parameters to Arthur and wait for his reply
	ArthurChann <- x0 // (2)
	ArthurChann <- x1

	// Recieve reply
	v := <-MerlinChann

	// Compute k0, k1 and encrypted messages
	// Exp(...) for modular exponentiation
	k0 := new(big.Int).Exp(new(big.Int).Sub(v, x0), d, N) // k0 := (v-x0)^(d) mod N
	k1 := new(big.Int).Exp(new(big.Int).Sub(v, x1), d, N) // k1 := (v-1)^(d) mod N

	// Mod(...) for modular reduction
	m0k := new(big.Int).Add(m0, k0).Mod(new(big.Int).Add(m0, k0), N) // m0k := (m0 + k0) % N
	m1k := new(big.Int).Add(m1, k1).Mod(new(big.Int).Add(m1, k1), N) // m0k := (m1 + k1) % N

	// Send the encrypted messages to
	ArthurChann <- m0k
	ArthurChann <- m1k
}

// Arthur's part of the 1-2 oblivious transfer
func ObliviousTransferArthur(b, n int, MerlinChann, ArthurChann chan *big.Int, wg *sync.WaitGroup) {
	defer wg.Done()
	rand.Seed(time.Now().UnixNano())

	if b != 0 && b != 1 {
		panic("b must be 0 or 1")
	}

	// Receive (text book) RSA parameters from Merlin (1)
	e := <-ArthurChann
	N := <-ArthurChann

	// Receive x0, x1
	x0 := <-ArthurChann
	x1 := <-ArthurChann

	// Generate k and compute v
	k := randBits(2048)

	var v *big.Int
	if b == 0 {
		v = new(big.Int).Add(x0, new(big.Int).Exp(k, e, N))
	} else { // if b is 1
		v = new(big.Int).Add(x1, new(big.Int).Exp(k, e, N))
	}

	v.Mod(v, N) // v % N

	// Send v to Merlin
	MerlinChann <- v

	// Receive encrypted messages
	m0k := <-ArthurChann
	m1k := <-ArthurChann

	// Decrypt the chosen message
	var mb *big.Int

	if b == 0 {
		mb = new(big.Int).Sub(m0k, k) // m0k - k
	} else {
		mb = new(big.Int).Sub(m1k, k) // m1k - k
	}
	mb.Mod(mb, N) // mb % N

	fmt.Println("Arthur received the message: ", mb) // mb has to be returned somewhere..
}
