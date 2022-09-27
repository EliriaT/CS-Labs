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

	for _, cipher := range cipherList {
		encryptedMessage := cipher.Encrypt("Hello. This message is encrypted.")
		fmt.Println(encryptedMessage)
		decryptedMessage := cipher.Decrypt(encryptedMessage)
		fmt.Println(decryptedMessage)
	}

}
