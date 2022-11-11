package main

import (
	"fmt"
	"github.com/EliriaT/CS-Labs/hash/message"
	"github.com/EliriaT/CS-Labs/hash/user"
	"log"
	"math/rand"
	"time"
)

func main() {
	rand.Seed(time.Now().UnixNano())

	userService := user.NewUserService(user.NewStore())

	// Registering a user
	err := userService.Register("irina", "averysecretpasswordandnoonecanfinditofcourse")
	if err != nil {
		log.Fatal("Something went wrong: ", err.Error())
	}

	// Logining the user. Inside, the password is checked by comparing with its stored hash
	loggedUser, err := userService.Login("irina", "averysecretpasswordandnoonecanfinditofcourse")
	if err != nil {
		log.Fatal("Something went wrong: ", err.Error())
	}

	// Representing the hash form of the password
	hashedPassword := loggedUser.Password
	fmt.Println("The hashed password of the user is: ", hashedPassword)

	// Getting an input message of the user from the terminal
	messageService := message.NewMessageService()
	messageService.GetMessageFromUser(&loggedUser)

	// Signing the message and getting back the signature and the hashedMessage
	signature, hashedBytesMessage, err := messageService.SignMessage(loggedUser.Message)
	if err != nil {
		log.Fatal("Something went wrong: ", err.Error())
	}

	// Checking the signature
	err = messageService.VerifyMessage(hashedBytesMessage, signature)
	if err != nil {
		log.Fatal("Message is not valid! ")
	}
	log.Println("The signature is valid. ")

}
