package main

import (
	"fmt"
	"github.com/EliriaT/CS-Labs/asymetricCipher/cipherInterface"
	"github.com/EliriaT/CS-Labs/asymetricCipher/rsa"
	"math/rand"
	"time"
)

func main() {
	rand.Seed(time.Now().UnixNano())
	//The list composed of objects that correspond to the Cipher interface
	cipherList := make([]cipherInterface.Cipher, 0)

	rsaCipher, _ := rsa.NewRSA()

	cipherList = append(cipherList, rsaCipher)

	//message: "iamirina"
	Message := []byte("i am irina.")

	for i, cipher := range cipherList {
		fmt.Println(i+1, ") ", "Message: ", string(Message), ". Encrypted using: ", cipher.Name())
		encryptedMessage, _ := cipher.Encrypt(Message)
		fmt.Println("The encrypted message: ", encryptedMessage)
		decryptedMessage, _ := cipher.Decrypt(encryptedMessage)
		fmt.Println("The decrypted message: ", string(decryptedMessage))
	}

}
