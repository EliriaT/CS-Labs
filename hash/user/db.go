package user

import "fmt"

type Database interface {
	Get(key string) (User, error)
	Set(key string, value User) error
}

type inMemDB struct {
	dataStore map[string]User
}

func (s inMemDB) Get(key string) (User, error) {
	value, ok := s.dataStore[key]

	if !ok {
		err := fmt.Errorf("No such value present with key %s", key)
		return User{}, err
	}

	return value, nil
}

func (s inMemDB) Set(key string, value User) error {
	s.dataStore[key] = value
	return nil
}

func NewStore() inMemDB {
	return inMemDB{
		dataStore: make(map[string]User),
	}
}
