package rsa

import (
	"fmt"
	"math/big"
	"math/rand"
)

// A PublicKey represents the public part of an RSA key.
type PublicKey struct {
	N   int64 // modulus
	E   int64 // public exponent
	phi int64
}

func (pk *PublicKey) setPublicKey() {

	lenPrimes := len(Primes)
	pInd := rand.Intn(lenPrimes)
	qInd := rand.Intn(lenPrimes)
	for qInd == pInd {
		qInd = rand.Intn(lenPrimes)
	}
	p := Primes[pInd]
	q := Primes[qInd]

	pk.N = int64(p) * int64(q)
	pk.E = 2
	pk.phi = (int64(p) - 1) * (int64(q) - 1)
	for pk.E < pk.phi {
		// e must be co-prime to phi and smaller than phi.
		if gcd(pk.E, pk.phi) == 1 && gcd(pk.E, pk.N) == 1 {
			break
		} else {
			pk.E++
		}
	}
}

// A PrivateKey represents an RSA key
type PrivateKey struct {
	PublicKey       // public part.
	d         int64 // private exponent
}

func (pk *PrivateKey) setPrKey(publicKey PublicKey) error {
	pk.PublicKey = publicKey

	//d is modular inverse of e mod phi
	pk.d = modInverse(pk.E, pk.phi)
	if pk.d == 0 {
		return fmt.Errorf("Can not set private key.")
	}
	return nil
}

func gcd(a int64, b int64) int64 {
	var temp int64
	for {
		temp = a % b
		if temp == 0 {
			return b
		}
		a = b
		b = temp
	}
}

func modInverse(a int64, m int64) int64 {
	var x int64
	for x = 1; x < m; x++ {
		if (a%m)*(x%m)%m == 1 {
			return x
		}
	}
	return 0
}

type RSA struct {
	PrivateKey
	PublicKey
}

func (r RSA) Encrypt(src []byte) ([]int64, error) {
	var encNums []int64
	for _, b := range src {
		encMessage := new(big.Int).SetBytes([]byte{b})
		encMessage = encMessage.Exp(encMessage, new(big.Int).SetInt64(r.E), new(big.Int).SetInt64(r.N))
		encNums = append(encNums, encMessage.Int64())
	}

	return encNums, nil
}
func (r RSA) Decrypt(src []int64) ([]byte, error) {

	var decBytes []byte
	for _, b := range src {
		decMessage := new(big.Int).SetInt64(b)
		decMessage = decMessage.Exp(decMessage, new(big.Int).SetInt64(r.d), new(big.Int).SetInt64(r.N))
		decBytes = append(decBytes, decMessage.Bytes()[0])
	}
	return decBytes, nil
}
func (r RSA) Name() string {
	return "RSA"
}

// NewRSA creates and returns a RSA cipher.
func NewRSA() (RSA, error) {
	var cipher RSA
	cipher.setPublicKey()
	cipher.setPrKey(cipher.PublicKey)
	return cipher, nil
}
