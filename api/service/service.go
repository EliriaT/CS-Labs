package service

import (
	"github.com/EliriaT/CS-Labs/api/db"
	"github.com/google/uuid"
	"github.com/pquerna/otp"
)

type Service interface {
	Register(username, password string, choice int) (db.User, *otp.Key, error)
	Login(Username string, password string) (db.User, error)
	CheckTOTP(username, totp string) (db.User, error)
	StoreAndEncryptMessage(username string, message string, encryptAlgorithm int) (db.Message, error)
	GetMessageFromDB(username string, messageID uuid.UUID) (string, error)
	GetMessagesOfUser(username string) ([]string, error)
}

type ServerService struct {
	MessageService
	UserService
}

func NewServerService(database db.Store) Service {
	return &ServerService{MessageService: NewMessageService(database), UserService: NewUserService(database)}
}
