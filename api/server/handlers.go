package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"github.com/EliriaT/CS-Labs/api/service"
	"github.com/EliriaT/CS-Labs/api/token"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"image/png"
	"net/http"
)

type createUserRequest struct {
	Username string      `json:"username" form:"username" binding:"required,min=3"`
	Password string      `json:"password" form:"password" binding:"required,min=6"`
	Choice   json.Number `json:"choice" form:"choice" binding:"required"`
}

type userRegisterResponse struct {
	ID         uuid.UUID `json:"id"`
	TOTPSecret string    `json:"authentificator_secret"`
	Qrcode     string    `json:"qrcode"`
}

func (server *Server) createUser(ctx *gin.Context) {
	var req createUserRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, ErrorResponse(err))
		return
	}

	choice, err := req.Choice.Int64()
	if err != nil {
		ctx.JSON(http.StatusBadRequest, ErrorResponse(err))
		return
	}
	user, key, err := server.serv.Register(req.Username, req.Password, int(choice))

	if err != nil {
		if err == service.ErrDuplicateUsername || err == service.ErrInvalidAlg {
			ctx.JSON(http.StatusBadRequest, ErrorResponse(err))
			return
		}
		ctx.JSON(http.StatusInternalServerError, ErrorResponse(err))
		return
	}

	var buf bytes.Buffer
	img, err := key.Image(200, 200)
	png.Encode(&buf, img)
	qrimage := base64.StdEncoding.EncodeToString(buf.Bytes())

	response := userRegisterResponse{
		user.Id,
		key.Secret(),
		qrimage,
	}
	ctx.JSON(http.StatusOK, response)
}

type loginUserRequest struct {
	Username string `json:"username" form:"username" binding:"required,min=3"`
	Password string `json:"password" form:"password" binding:"required,min=6"`
}

type loginUserResponse struct {
	AccessToken string    `json:"access_token"`
	UserID      uuid.UUID `json:"user"`
}

func (server *Server) loginUser(ctx *gin.Context) {
	var req loginUserRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, ErrorResponse(err))
		return
	}

	user, err := server.serv.Login(req.Username, req.Password)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, ErrorResponse(err))
		return
	}

	accessToken, err := server.tokenMaker.CreateToken(user.Username, server.config.AccessTokenDuration)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, ErrorResponse(err))
		return
	}

	response := loginUserResponse{
		AccessToken: accessToken,
		UserID:      user.Id,
	}
	ctx.JSON(http.StatusOK, response)
}

type twoFactorAuthRequest struct {
	Totp string `json:"totp" form:"totp" binding:"required"`
}

type twoFactorAuthResponse struct {
	AccessToken string    `json:"access_token"`
	UserID      uuid.UUID `json:"user"`
}

func (server *Server) twoFactorLoginUser(ctx *gin.Context) {
	var req twoFactorAuthRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, ErrorResponse(err))
		return
	}

	authPayload := ctx.MustGet(authorizationPayloadKey).(*token.Payload)

	user, err := server.serv.CheckTOTP(authPayload.Username, req.Totp)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, ErrorResponse(err))
		return
	}

	authToken, err := server.tokenMaker.AuthenticateToken(*authPayload)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, ErrorResponse(err))
		return
	}

	response := twoFactorAuthResponse{
		AccessToken: authToken,
		UserID:      user.Id,
	}
	ctx.JSON(http.StatusOK, response)
}

type createMessageRequest struct {
	Message string      `json:"message" form:"message" binding:"required,min=4"`
	Choice  json.Number `json:"choice" form:"choice" binding:"required"`
}

func (server *Server) createMessage(ctx *gin.Context) {
	var req createMessageRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, ErrorResponse(err))
		return
	}

	choice, err := req.Choice.Int64()
	if err != nil {
		ctx.JSON(http.StatusBadRequest, ErrorResponse(err))
		return
	}

	authPayload := ctx.MustGet(authorizationPayloadKey).(*token.Payload)

	message, err := server.serv.StoreAndEncryptMessage(authPayload.Username, req.Message, int(choice))
	if err != nil {
		if err == service.ErrEncryption || err == service.ErrUUID {
			ctx.JSON(http.StatusInternalServerError, ErrorResponse(err))
			return
		}
		ctx.JSON(http.StatusUnauthorized, ErrorResponse(err))
		return
	}

	ctx.JSON(http.StatusOK, message)
}

func (server *Server) getUserMessageByID(ctx *gin.Context) {
	messageID := ctx.Param("id")

	authPayload := ctx.MustGet(authorizationPayloadKey).(*token.Payload)

	message, err := server.serv.GetMessageFromDB(authPayload.Username, uuid.MustParse(messageID))
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, ErrorResponse(err))
		return
	}

	ctx.JSON(http.StatusOK, message)
}

func (server *Server) getMessagesOfUser(ctx *gin.Context) {

	authPayload := ctx.MustGet(authorizationPayloadKey).(*token.Payload)

	messages, err := server.serv.GetMessagesOfUser(authPayload.Username)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, ErrorResponse(err))
		return
	}

	ctx.JSON(http.StatusOK, messages)
}
