package token

import (
	"fmt"
	"github.com/o1egl/paseto"
	"golang.org/x/crypto/chacha20poly1305"
	"time"
)

// PasetoMaker is a PASETO token maker which implements the TokenMaker interface
type PasetoMaker struct {
	paseto       *paseto.V2
	symmetricKey []byte
}

// CreateToken creates a new token for a specific hash with unique username,
func (p *PasetoMaker) CreateToken(username string, duration time.Duration) (string, error) {
	payload, err := NewPayload(username, duration)
	if err != nil {
		return "", err
	}

	return p.paseto.Encrypt(p.symmetricKey, payload, nil)
}

// AuthenticateToken marks authentitcated field in the token payload as true, after 2fa is succesful,
func (p *PasetoMaker) AuthenticateToken(payload Payload) (string, error) {

	payload.Authenticated = true

	return p.paseto.Encrypt(p.symmetricKey, payload, nil)
}

// VerifyToken checks if the tocken is valid, or not and returns the decrypted payload
func (p *PasetoMaker) VerifyToken(token string) (*Payload, error) {
	payload := &Payload{}

	err := p.paseto.Decrypt(token, p.symmetricKey, payload, nil)
	if err != nil {
		return nil, ErrInvalidToken
	}

	err = payload.Valid()
	if err != nil {
		return nil, err
	}
	return payload, nil
}

// NewPasetoMaker creates a new PasetoMaker
func NewPasetoMaker(symmetricKey string) (TokenMaker, error) {
	if len(symmetricKey) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("invalid key size: must be at %d characthers length", chacha20poly1305.KeySize)
	}

	tokenMaker := &PasetoMaker{
		paseto:       paseto.NewV2(),
		symmetricKey: []byte(symmetricKey),
	}
	return tokenMaker, nil
}
