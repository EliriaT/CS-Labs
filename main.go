package main

import (
	"encoding/base64"
	"fmt"
	"github.com/EliriaT/CS-Labs/streamBlockCipher/blowfish"
	"github.com/EliriaT/CS-Labs/streamBlockCipher/cipherInterface"
	"github.com/EliriaT/CS-Labs/streamBlockCipher/oneTimePad"
	"log"
	"math/rand"
	"time"
)

func main() {
	rand.Seed(time.Now().UnixNano())
	//The list composed of objects that correspond to the Cipher interface
	cipherList := make([]cipherInterface.Cipher, 0)

	//the 8 bytes long key for Blowfish
	keyBlowfish := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}
	//It returns a Blowfish object
	blowfishCipher, err := blowfish.NewBlowfish(keyBlowfish)
	if err != nil {
		log.Panicf("blowfishCipher error( %d bytes) = %s", len(keyBlowfish), err)
	}

	cipherList = append(cipherList, blowfishCipher)

	//initializing the list of 16*2048 bytes for the otp key. Each page of pad the  will be of size 16 bytes, in total 2048 pages
	keyOTP := make([]byte, 16*2048)
	//Generating random bits
	rand.Read(keyOTP)
	//It returns a new OTP object , and sets the page to 1
	otpCipher, err := oneTimePad.NewPad(keyOTP, 16, 1)
	if err != nil {
		fmt.Printf("%s", err)
		return
	}

	cipherList = append(cipherList, otpCipher)

	//64 bits message, "iamirina"
	Message := []byte{0x69, 0x61, 0x6d, 0x69, 0x72, 0x69, 0x6e, 0x61}

	for i, cipher := range cipherList {
		fmt.Println(i+1, ") ", "Encrypted using: ", cipher.Name())
		encryptedMessage, _ := cipher.Encrypt(Message)
		fmt.Println("The encrypted message: ", base64.StdEncoding.EncodeToString(encryptedMessage))
		decryptedMessage, _ := cipher.Decrypt(encryptedMessage)
		fmt.Println("The decrypted message: ", string(decryptedMessage))
	}

}
