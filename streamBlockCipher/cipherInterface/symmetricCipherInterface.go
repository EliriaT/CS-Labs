package cipherInterface

type SymmetricCipher interface {
	Encrypt(src []byte) ([]byte, error)
	Decrypt(src []byte) ([]byte, error)
	Name() string
}
