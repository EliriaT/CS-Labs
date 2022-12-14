package service

import (
	"github.com/EliriaT/CS-Labs/api/db"
	"github.com/EliriaT/CS-Labs/hash/hash"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

var (
	ErrDuplicateUsername = errors.New("person with such username already exists")
	ErrWrongOTPCode      = errors.New("wrong OTP provided")
)

type UserService interface {
	Register(username, password string, choice int) (db.User, *otp.Key, error)
	Login(Username string, password string) (db.User, error)
	CheckTOTP(username, totp string) (db.User, error)
}

type userService struct {
	db db.Store
}

func (s *userService) Register(username, password string, choice int) (db.User, *otp.Key, error) {

	_, err := s.db.GetUser(username)
	if err == nil {
		return db.User{}, nil, ErrDuplicateUsername
	}

	hashedPassword, err := hash.HashPassword(password)
	if err != nil {
		return db.User{}, nil, err
	}

	userId, err := uuid.NewRandom()
	if err != nil {
		return db.User{}, nil, err
	}

	if choice < int(db.ClassicUser) || choice > int(db.SymmetricUser) {
		return db.User{}, nil, ErrInvalidAlg
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "CSFAFLabs.utm",
		AccountName: username,
	})

	user := db.User{
		Id:         userId,
		Username:   username,
		Password:   hashedPassword,
		Choice:     db.CipherChoice(choice),
		TOTPSecret: key.Secret(),
	}

	s.db.StoreUser(&user)
	return user, key, s.db.SetUser(username, user)
}

func (s *userService) Login(username, password string) (db.User, error) {
	user, err := s.db.GetUser(username)
	if err != nil {
		return db.User{}, err
	}
	if err = hash.CheckPassword(password, user.Password); err != nil {
		return db.User{}, err
	}
	return user, nil
}

func (s *userService) CheckTOTP(username, totpToken string) (db.User, error) {
	user, err := s.db.GetUser(username)
	if err != nil {
		return db.User{}, err
	}

	valid := totp.Validate(totpToken, user.TOTPSecret)
	if !valid {
		return db.User{}, ErrWrongOTPCode
	}
	return user, nil
}

func NewUserService(database db.Store) UserService {
	return &userService{db: database}
}
