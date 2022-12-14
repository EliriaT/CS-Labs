package token

import (
	"github.com/EliriaT/CS-Labs/api/db"
	"time"
)

type TokenMaker interface {
	// CreateToken creates a new token for a specific hash with unique email,
	CreateToken(username string, cipherGroup db.CipherChoice, duration time.Duration) (string, error)

	// VerifyToken checks if the tocken is valid, or not
	VerifyToken(token string) (*Payload, error)

	// AuthentificateToken marks authentitcated field in the token payload as true, after 2fa is succesful,
	AuthentificateToken(payload Payload) (string, error)
}
