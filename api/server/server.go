package server

import (
	"fmt"
	"github.com/EliriaT/CS-Labs/api/config"
	"github.com/EliriaT/CS-Labs/api/db"
	"github.com/EliriaT/CS-Labs/api/service"
	"github.com/EliriaT/CS-Labs/api/token"
	"github.com/gin-gonic/gin"
)

// Serves for HTTP requests
type Server struct {
	store      db.Store
	tokenMaker token.TokenMaker
	router     *gin.Engine
	config     config.Config
	serv       service.Service
}

func NewServer(store db.Store, config config.Config, serv service.Service) (*Server, error) {
	tokenMaker, err := token.NewPasetoMaker(config.TokenSymmetricKey)
	if err != nil {
		return nil, fmt.Errorf("cannot create token maker: %w", err)
	}
	server := &Server{
		store:      store,
		tokenMaker: tokenMaker,
		config:     config,
		serv:       serv,
	}

	server.setupRouter()
	return server, nil
}

func (server *Server) setupRouter() {
	router := gin.Default()

	router.POST("/users", server.createUser)
	router.POST("/users/login", server.loginUser)
	router.POST("/users/twofactor", AuthMiddleware(server.tokenMaker), server.twoFactorLoginUser)

	authRoutes := router.Group("/message").Use(AuthMiddleware(server.tokenMaker))

	authRoutes.POST("", server.createMessage)
	authRoutes.GET("/:id", server.getUserMessageByID)
	authRoutes.GET("/all", server.getMessagesOfUser)

	server.router = router
}

// Starts the HTTP server
func (server *Server) Start(address string) error {
	return server.router.Run(address)
}

func ErrorResponse(err error) gin.H {
	return gin.H{"error": err.Error()}
}
