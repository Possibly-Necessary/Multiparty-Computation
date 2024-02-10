package main

import (
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"fmt"
	"io"
	"math/big"
)
// ____________________________ Symmetric Cryptography: AES-GCM ____________________________________
func symmetricEnc(key []byte, x *big.Int) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(crand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	plaintext := x.Bytes()
	ciphertext := aesGCM.Seal(nil, nonce, plaintext, nil) // The tag is included in ciphertext

	return ciphertext, nonce, nil
}

func symmetricDec(key []byte, ciphertext, nonce []byte) (*big.Int, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil) // ciphertext includes the tag
	if err != nil {
		return nil, err
	}

	if len(plaintext) < 8 {
		return nil, fmt.Errorf("decrypted plaintext is too short")
	}

	// Convert plaintext []byte to *big.Int
	x := new(big.Int).SetBytes(plaintext)

	return x, nil
}
