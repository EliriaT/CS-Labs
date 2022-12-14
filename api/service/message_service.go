package service

import (
	"fmt"
	"github.com/EliriaT/CS-Labs/api/db"
	"github.com/EliriaT/CS-Labs/asymetricCipher/rsa"
	"github.com/EliriaT/CS-Labs/classicCipher/Caesar"
	"github.com/EliriaT/CS-Labs/classicCipher/CaesarPermutation"
	"github.com/EliriaT/CS-Labs/classicCipher/Playfair"
	"github.com/EliriaT/CS-Labs/classicCipher/Vigener"
	"github.com/EliriaT/CS-Labs/streamBlockCipher/blowfish"
	"github.com/EliriaT/CS-Labs/streamBlockCipher/oneTimePad"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"log"
	"math/rand"
	"strconv"
	"strings"
)

// Different types of error returned by the VerifyToken function
var (
	ErrInvalidAlg      = errors.New("Invalid encryption algorithm")
	ErrUnauthorisedAlg = errors.New("Not authorized to use this algorithm")
	ErrEncryption      = errors.New("Unknown encryption or decryption error")
	ErrUUID            = errors.New("UUID error")
	ErrUnauthorized    = errors.New("User is not authorized ")
)

var (
	caesarCipher            Caesar.CaesarCipher
	caesarPermutationCipher CaesarPermutation.CaesarPermutationCipher
	vigenereCipher          Vigener.VigenereCipher
	playfairCipher          Playfair.PlayfairCipher
	blowfishCipher          *blowfish.Blowfish
	otpCipher               *oneTimePad.Pad
	rsaCipher               rsa.RSA
)

type MessageService interface {
	StoreAndEncryptMessage(username string, message string, encryptAlgorithm int) (db.Message, error)
	GetMessageFromDB(username string, messageID uuid.UUID) (string, error)
	GetMessagesOfUser(username string) ([]string, error)
}

type messageService struct {
	db db.Store
}

func NewMessageService(database db.Store) MessageService {
	return &messageService{db: database}
}

func (m *messageService) StoreAndEncryptMessage(username string, message string, encryptAlgorithm int) (db.Message, error) {
	user, err := m.db.GetUser(username)
	if err != nil {
		return db.Message{}, err
	}

	if encryptAlgorithm < int(db.Rsa) || encryptAlgorithm > int(db.OneTimePad) {
		return db.Message{}, ErrInvalidAlg
	}

	chiperGroup := user.Choice
	isPresent := false
	for _, alg := range db.CipherRoles[chiperGroup] {
		if int(alg) == encryptAlgorithm {
			isPresent = true
		}
	}
	if isPresent == false {
		return db.Message{}, ErrUnauthorisedAlg
	}

	encryptedMessage := encryptMessage(db.EncryptionAlg(encryptAlgorithm), message)
	if encryptedMessage == nil {
		return db.Message{}, ErrEncryption
	}

	messageId, err := uuid.NewRandom()
	if err != nil {
		return db.Message{}, ErrUUID
	}

	dbMessage := db.Message{
		Id:               messageId,
		EncryptedMessage: encryptedMessage,
		EncryptionAlg:    db.EncryptionAlg(encryptAlgorithm),
		Author:           username,
	}
	m.db.StoreMessage(&dbMessage)
	return dbMessage, nil
}

func (m *messageService) GetMessageFromDB(username string, messageID uuid.UUID) (string, error) {
	_, err := m.db.GetUser(username)
	if err != nil {
		return "", ErrUnauthorized
	}

	message, err := m.db.GetMessage(messageID)
	if err != nil {
		return "", ErrUnauthorized
	}

	if message.Author != username {
		return "", ErrUnauthorized
	}

	decrypted := decryptMessage(message.EncryptionAlg, message)
	if decrypted == nil {
		return "", ErrEncryption
	}
	return string(decrypted), nil

}

func (m *messageService) GetMessagesOfUser(username string) ([]string, error) {
	_, err := m.db.GetUser(username)
	if err != nil {
		return nil, ErrUnauthorized
	}

	userMessages, err := m.db.GetMessagesOfUser(username)
	if err != nil {
		return nil, ErrUnauthorized
	}

	var messages []string

	for _, message := range userMessages {
		bytes := decryptMessage(message.EncryptionAlg, message)
		messages = append(messages, string(bytes))
	}
	return messages, nil
}

func decryptMessage(alg db.EncryptionAlg, message db.Message) []byte {

	switch alg {
	case db.Rsa:
		encNumsStr := strings.Split(strings.Trim(string(message.EncryptedMessage), "[]"), " ")
		encNums := make([]int64, 0)
		for _, num := range encNumsStr {
			numInt, _ := strconv.Atoi(num)
			encNums = append(encNums, int64(numInt))
		}
		decryptedMessage, _ := rsaCipher.Decrypt(encNums)
		return decryptedMessage
	case db.Caesar:
		decryptedMessage := caesarCipher.Decrypt(string(message.EncryptedMessage))
		return []byte(decryptedMessage)
	case db.CaesarPerm:
		decryptedMessage := caesarPermutationCipher.Decrypt(string(message.EncryptedMessage))
		return []byte(decryptedMessage)
	case db.Playfair:
		decryptedMessage := playfairCipher.Decrypt(string(message.EncryptedMessage))
		return []byte(decryptedMessage)
	case db.Vigener:
		decryptedMessage := vigenereCipher.Decrypt(string(message.EncryptedMessage))
		return []byte(decryptedMessage)
	case db.Blowfish:
		decryptedMessage, _ := blowfishCipher.Decrypt(message.EncryptedMessage)
		return decryptedMessage
	case db.OneTimePad:
		decryptedMessage, _ := otpCipher.Decrypt(message.EncryptedMessage)
		return decryptedMessage

	}
	return nil
}

func encryptMessage(alg db.EncryptionAlg, message string) []byte {

	switch alg {
	case db.Rsa:
		encryptedMessage, _ := rsaCipher.Encrypt([]byte(message))
		return []byte(fmt.Sprint(encryptedMessage))
	case db.Caesar:
		encryptedMessage := caesarCipher.Encrypt(message)
		return []byte(encryptedMessage)
	case db.CaesarPerm:
		encryptedMessage := caesarPermutationCipher.Encrypt(message)
		return []byte(encryptedMessage)
	case db.Playfair:
		encryptedMessage := playfairCipher.Encrypt(message)
		return []byte(encryptedMessage)
	case db.Vigener:
		encryptedMessage := vigenereCipher.Encrypt(message)
		return []byte(encryptedMessage)
	case db.Blowfish:
		encryptedMessage, _ := blowfishCipher.Encrypt([]byte(message))
		return encryptedMessage
	case db.OneTimePad:
		encryptedMessage, _ := otpCipher.Encrypt([]byte(message))
		return encryptedMessage

	}
	return nil
}

func MakeCiphers() {
	caesarCipher = Caesar.MakeCaesarCipher()
	caesarCipher.SetKey(4)

	caesarPermutationCipher = CaesarPermutation.MakeCaesarPermutationCipher()
	caesarPermutationCipher.SetKey(0)

	vigenereCipher = Vigener.MakeVigenereCipher("thisisasamplekey")

	playfairCipher = Playfair.MakePlayfairCipher("thisisasamplekey")

	//the 8 bytes long key for Blowfish
	keyBlowfish := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}
	//It returns a Blowfish object
	var err error
	blowfishCipher, err = blowfish.NewBlowfish(keyBlowfish)
	if err != nil {
		log.Panicf("blowfishCipher error( %d bytes) = %s", len(keyBlowfish), err)
	}

	//initializing the list of 16*2048 bytes for the otp key. Each page of pad the  will be of size 16 bytes, in total 2048 pages
	keyOTP := make([]byte, 16*2048)
	//Generating random bits
	rand.Read(keyOTP)
	//It returns a new OTP object , and sets the page to 1
	otpCipher, err = oneTimePad.NewPad(keyOTP, 16, 1)
	if err != nil {
		fmt.Printf("%s", err)

	}

	rsaCipher, _ = rsa.NewRSA()

}
