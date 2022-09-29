package main

import (
	"fmt"
	"github.com/EliriaT/CS-Labs/Lab1/implementations"
	"math/rand"
	"time"
)

func main() {
	rand.Seed(time.Now().UnixNano())
	cipherList := make([]Cipher, 0)

	caesarCipher := implementations.MakeCaesarCipher()
	caesarCipher.SetKey(4)
	cipherList = append(cipherList, caesarCipher)

	caesarPermutationCipher := implementations.MakeCaesarPermutationCipher()
	caesarPermutationCipher.SetKey(0)
	cipherList = append(cipherList, caesarPermutationCipher)

	vigenereCipher := implementations.MakeVigenereCipher("thisisasamplekey")
	cipherList = append(cipherList, vigenereCipher)

	playfairCipher := implementations.MakePlayfairCipher("thisisasamplekey")
	cipherList = append(cipherList, playfairCipher)

	for i, cipher := range cipherList {
		fmt.Println(i+1, ") ", "Encrypted using: ", cipher.Name())
		encryptedMessage := cipher.Encrypt("Hi. This message is veeeryyy secret")
		fmt.Println("The encrypted message: ", encryptedMessage)
		decryptedMessage := cipher.Decrypt(encryptedMessage)
		fmt.Println("The decrypted message: ", decryptedMessage)
	}

}
