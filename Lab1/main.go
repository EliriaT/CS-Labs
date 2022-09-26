package main

import (
	"fmt"
	"github.com/EliriaT/CS-Labs/Lab1/implementations"
)

func main() {
	caesarCipher := implementations.MakeCaesarCipher()
	caesarCipher.SetKey(4)
	encryptedMessage := caesarCipher.Encrypt("ATTACKATONCE")
	fmt.Println(encryptedMessage)
	decryptedMessage := caesarCipher.Decrypt(encryptedMessage)
	fmt.Println(decryptedMessage)
}
