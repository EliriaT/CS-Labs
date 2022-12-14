package token

import (
	"time"
)

type TokenMaker interface {
	// CreateToken creates a new token for a specific hash with unique email,
	CreateToken(username string, duration time.Duration) (string, error)

	// VerifyToken checks if the tocken is valid, or not
	VerifyToken(token string) (*Payload, error)

	// AuthentificateToken marks authentitcated field in the token payload as true, after 2fa is succesful,
	AuthenticateToken(payload Payload) (string, error)
}
