package cipherInterface

type Cipher interface {
	Encrypt(text string) string
	Decrypt(text string) string
	Name() string
}
