package user

import (
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"golang.org/x/crypto/bcrypt"
)

type UserService interface {
	Register(Username string, password string) error
	Login(Username string, password string) (User, error)
}

type userService struct {
	db Database
}

func (s *userService) Register(username, password string) error {

	_, err := s.db.Get(username)
	if err == nil {
		return errors.New("user with such username already exists")
	}

	hashedPassword, err := HashPassword(password)
	if err != nil {
		return err
	}

	user := User{
		Username: username,
		Password: hashedPassword,
	}

	return s.db.Set(username, user)
}

func (s *userService) Login(username, password string) (User, error) {
	user, err := s.db.Get(username)
	if err != nil {
		return User{}, err
	}
	if err = CheckPassword(password, user.Password); err != nil {
		return user, nil
	}
	return User{}, err
}

// Returns the bcrypt hash of the password
func HashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("Failed to hash the password")
	}
	return hexutil.Encode(hashedPassword), nil
}

// Checks if the provided password is correct, nil if correct, error if wrong
func CheckPassword(password string, hashedPassword string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

func NewUserService(database Database) UserService {
	return &userService{db: database}
}
