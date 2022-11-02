package cipherInterface

type Cipher interface {
	Encrypt(src []byte) ([]int64, error)
	Decrypt(src []int64) ([]byte, error)
	Name() string
}
