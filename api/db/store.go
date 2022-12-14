package db

import (
	"fmt"
	"github.com/google/uuid"
)

type Store interface {
	StoreMessage(message *Message)
	StoreUser(user *User)
	GetUser(key string) (User, error)
	SetUser(key string, value User) error
	GetMessage(id uuid.UUID) (Message, error)
	GetMessagesOfUser(username string) ([]Message, error)
}

type InMemStore struct {
	UserById           map[uuid.UUID]*User
	UserByUsername     map[string]User
	MessageById        map[uuid.UUID]*Message
	MessagesByUsername map[string][]Message
}

func (store *InMemStore) GetUser(key string) (User, error) {
	value, ok := store.UserByUsername[key]

	if !ok {
		err := fmt.Errorf("No such value present with key %s", key)
		return User{}, err
	}

	return value, nil
}

func (store *InMemStore) SetUser(key string, value User) error {
	store.UserByUsername[key] = value
	return nil
}

func (store *InMemStore) StoreMessage(message *Message) {
	store.MessageById[message.Id] = message
	store.MessagesByUsername[message.Author] = append(store.MessagesByUsername[message.Author], *message)
}

func (store *InMemStore) StoreUser(user *User) {
	store.UserById[user.Id] = user
	_ = store.SetUser(user.Username, *user)
}

func (store *InMemStore) GetMessage(id uuid.UUID) (Message, error) {
	message, ok := store.MessageById[id]
	if !ok {
		err := fmt.Errorf("No such value present with key %s", id)
		return Message{}, err
	}
	return *message, nil
}

func (store *InMemStore) GetMessagesOfUser(username string) ([]Message, error) {
	message, ok := store.MessagesByUsername[username]
	if !ok {
		err := fmt.Errorf("No such value present with key %s", username)
		return nil, err
	}
	return message, nil
}

func NewStore() Store {
	return &InMemStore{
		UserById:           map[uuid.UUID]*User{},
		UserByUsername:     map[string]User{},
		MessageById:        map[uuid.UUID]*Message{},
		MessagesByUsername: map[string][]Message{},
	}
}
