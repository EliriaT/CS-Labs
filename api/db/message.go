package db

import "github.com/google/uuid"

type Message struct {
	Id               uuid.UUID     `json:"id"`
	EncryptedMessage []byte        `json:"encrypted_message"`
	EncryptionAlg    EncryptionAlg `json:"encryption_alg"`
	Author           string        `json:"author"`
}

type EncryptionAlg int

const (
	Rsa EncryptionAlg = iota
	Caesar
	CaesarPerm
	Playfair
	Vigener
	Blowfish
	OneTimePad
)
