package message

import (
	"bytes"
	"crypto/ecdsa"
	"fmt"
	"github.com/EliriaT/CS-Labs/hash/user"
	"github.com/ethereum/go-ethereum/crypto"
	"log"
)

type MessageService interface {
	GetMessageFromUser(loggedUser *user.User)
	SignMessage(msg string) ([]byte, []byte, error)
	VerifyMessage(hashedMessage, signature []byte) error
}

type messageService struct {
	privateKey *ecdsa.PrivateKey
}

func (m messageService) GetMessageFromUser(loggedUser *user.User) {
	var inputMessage string
	fmt.Println("Enter your message please : ")
	fmt.Scanln(&inputMessage)
	loggedUser.Message = inputMessage

}

func (m messageService) SignMessage(message string) ([]byte, []byte, error) {
	//Keccak-256 as the hashing algorithm
	hash := crypto.Keccak256Hash([]byte(message))
	signature, err := crypto.Sign(hash.Bytes(), m.privateKey)
	if err != nil {
		return nil, nil, err
	}
	return signature, hash.Bytes(), nil
}

func (m messageService) VerifyMessage(hashedMessage, signature []byte) error {
	publicKey := m.privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("error casting public key to ECDSA")
	}

	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)
	// Ecrecover (elliptic curve signature recover) from the go-ethereum crypto package to retrieve the public key of the signer.
	sigPublicKey, err := crypto.Ecrecover(hashedMessage, signature)
	if err != nil {
		log.Fatal(err)
	}
	// Comparing the signature's public key with the expected public key and if they match then the expected public key holder is indeed the signer of the original message
	matches := bytes.Equal(sigPublicKey, publicKeyBytes)
	if !matches {
		return fmt.Errorf("Signature is not valid!!")
	}
	return nil
}

func NewMessageService() MessageService {
	privateKey, err := crypto.HexToECDSA("fad9c8855b740a0b7ed4c221dbad0f33a83a49cad6b3fe8d5817ac83d38b6a19")
	if err != nil {
		log.Fatal(err)
	}
	return messageService{
		privateKey: privateKey,
	}
}
