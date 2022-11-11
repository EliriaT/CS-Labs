package cipherInterface

type ClassicCipher interface {
	Encrypt(text string) string
	Decrypt(text string) string
	Name() string
}
