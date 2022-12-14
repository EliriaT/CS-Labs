package main

import (
	"encoding/base32"
	"fmt"
	"github.com/EliriaT/CS-Labs/api/config"
	"github.com/EliriaT/CS-Labs/api/db"
	"github.com/EliriaT/CS-Labs/api/server"
	"github.com/EliriaT/CS-Labs/api/service"
	"log"
	"math/rand"
	"time"
)

func main() {
	rand.Seed(time.Now().UnixNano())

	random := make([]byte, 10)
	rand.Read(random)
	secret := base32.StdEncoding.EncodeToString(random)
	fmt.Println(secret)

	service.MakeCiphers()

	configuration := config.LoadConfig()

	store := db.NewStore()

	apiServer, err := server.NewServer(store, configuration, service.NewServerService(store))

	if err != nil {
		log.Fatal("cannot create new server: ", err)
	}

	log.Println("Server is starting...")
	err = apiServer.Start(configuration.ServerAddress)

	if err != nil {
		log.Fatal("server can not be started. ", err)
	}
}
