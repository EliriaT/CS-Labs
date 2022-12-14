package token

import (
	"errors"
	"github.com/google/uuid"
	"time"
)

// Different types of error returned by the VerifyToken function
var (
	ErrInvalidToken = errors.New("token is invalid")
	ErrExpiredToken = errors.New("token has expired")
)

// Payload contains the payload data of the token
type Payload struct {
	ID            uuid.UUID `json:"id"`
	Username      string    `json:"username"`
	Authenticated bool      `json:"authenticated"`
	IssuedAt      time.Time `json:"issued_at"`
	ExpiredAt     time.Time `json:"expired_at"`
}

// Valid checks if the token payload is valid or not
func (payload *Payload) Valid() error {
	if time.Now().After(payload.ExpiredAt) {
		return ErrExpiredToken
	}
	return nil
}

func NewPayload(username string, duration time.Duration) (*Payload, error) {
	tokenId, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}

	// I should have here User ID which is a uuid, and hash role
	payload := &Payload{
		ID:            tokenId,
		Username:      username,
		Authenticated: false,
		IssuedAt:      time.Now(),
		ExpiredAt:     time.Now().Add(duration),
		//RegisteredClaims: jwt.RegisteredClaims{
		//	ExpiresAt: jwt.NewNumericDate(time.Now().Add(duration)),
		//	IssuedAt:  jwt.NewNumericDate(time.Now()),
		//	NotBefore: jwt.NewNumericDate(time.Now()),
		//},
	}
	return payload, nil
}
