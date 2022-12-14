package db

import "github.com/google/uuid"

type CipherChoice int

const (
	ClassicUser CipherChoice = iota
	AssymetricUser
	SymmetricUser
)

var CipherRoles = map[CipherChoice][]EncryptionAlg{
	ClassicUser:    {Caesar, CaesarPerm, Playfair, Vigener},
	AssymetricUser: {Rsa},
	SymmetricUser:  {Blowfish, OneTimePad},
}

type User struct {
	Id         uuid.UUID
	Username   string       `json:"username"`
	Password   string       `json:"password"`
	Choice     CipherChoice `json:"choice"`
	TOTPSecret string
}
