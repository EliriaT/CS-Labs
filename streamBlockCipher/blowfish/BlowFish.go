package blowfish

import (
	"strconv"
)

const BlockSize = 8

type Blowfish struct {
	p              [18]uint32
	s0, s1, s2, s3 [256]uint32
}

// Encrypt encrypts the 8-byte buffer src using the key k
// and stores the result in dst.
// Note that for amounts of data larger than a block,
// it is not safe to just call Encrypt on successive blocks;
// instead, use an encryption mode like CBC (see crypto/cipher/cbc.go).
func (c *Blowfish) Encrypt(src []byte) ([]byte, error) {
	var dst []byte
	dst = make([]byte, 8)

	l := uint32(src[0])<<24 | uint32(src[1])<<16 | uint32(src[2])<<8 | uint32(src[3])
	r := uint32(src[4])<<24 | uint32(src[5])<<16 | uint32(src[6])<<8 | uint32(src[7])
	l, r = encryptBlock(l, r, c)
	dst[0], dst[1], dst[2], dst[3] = byte(l>>24), byte(l>>16), byte(l>>8), byte(l)
	dst[4], dst[5], dst[6], dst[7] = byte(r>>24), byte(r>>16), byte(r>>8), byte(r)

	return dst, nil
}

// Decrypt decrypts the 8-byte buffer src using the key k
// and stores the result in dst.
func (c *Blowfish) Decrypt(src []byte) ([]byte, error) {
	var dst []byte
	dst = make([]byte, 8)

	l := uint32(src[0])<<24 | uint32(src[1])<<16 | uint32(src[2])<<8 | uint32(src[3])
	r := uint32(src[4])<<24 | uint32(src[5])<<16 | uint32(src[6])<<8 | uint32(src[7])
	l, r = decryptBlock(l, r, c)
	dst[0], dst[1], dst[2], dst[3] = byte(l>>24), byte(l>>16), byte(l>>8), byte(l)
	dst[4], dst[5], dst[6], dst[7] = byte(r>>24), byte(r>>16), byte(r>>8), byte(r)

	return dst, nil
}

func (c *Blowfish) Name() string {
	return "Blowfish"
}

type KeySizeError int

func (k KeySizeError) Error() string {
	return "invalid key size for blowfish" + strconv.Itoa(int(k))
}

// NewBlowfish creates and returns a  Blowfish cipher.
// The key argument should be the Blowfish key, from 4 to 56 bytes.
func NewBlowfish(key []byte) (*Blowfish, error) {
	var result Blowfish
	if k := len(key); k < 1 || k > 56 {
		return nil, KeySizeError(k)
	}
	initCipher(&result)
	ExpandKey(key, &result)
	return &result, nil
}

func initCipher(c *Blowfish) {
	copy(c.p[0:], p[0:])
	copy(c.s0[0:], s0[0:])
	copy(c.s1[0:], s1[0:])
	copy(c.s2[0:], s2[0:])
	copy(c.s3[0:], s3[0:])
}
