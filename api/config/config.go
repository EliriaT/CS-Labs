package config

import "time"

type Config struct {
	ServerAddress       string        `mapstructure:"SERVER_ADDRESS"`
	TokenSymmetricKey   string        `mapstructure:"TOKEN_SYMMETRIC_KEY"`
	AccessTokenDuration time.Duration `mapstructure:"ACCESS_TOKEN_DURATION"`
}

func LoadConfig() Config {
	config := Config{}
	config.ServerAddress = ":8080"
	config.TokenSymmetricKey = "12345678901234567890123456789012"
	config.AccessTokenDuration = 150 * time.Minute
	return config
}
