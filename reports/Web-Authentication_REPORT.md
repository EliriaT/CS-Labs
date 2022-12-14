# Topic: Web Authentication & Authorisation.

### Course: Cryptography & Security
### Author: Vasile Drumea

----

## Overview

&ensp;&ensp;&ensp; Authentication & authorization are 2 of the main security goals of IT systems and should not be used interchangibly. Simply put, 
during authentication the system verifies the identity of a user or service, and during authorization the system checks the access rights, 
optionally based on a given user role.

&ensp;&ensp;&ensp; There are multiple types of authentication based on the implementation mechanism or the data provided by the user. 
Some usual ones would be the following:
- Based on credentials (Username/Password);
- Multi-Factor Authentication (2FA, MFA);
- Based on digital certificates;
- Based on biometrics;
- Based on tokens.

&ensp;&ensp;&ensp; Regarding authorization, the most popular mechanisms are the following:
- Role Based Access Control (RBAC): Base on the role of a user;
- Attribute Based Access Control (ABAC): Based on a characteristic/attribute of a user.


## Objectives:
1. Take what you have at the moment from previous laboratory works and put it in a web service / serveral web services.
2. Your services should have implemented basic authentication and MFA (the authentication factors of your choice).
3. Your web app needs to simulate user authorization and the way you authorise user is also a choice that needs to be done by you.
4. As services that your application could provide, the classical ciphers could be used . Basically the user would like to get access and use the classical ciphers, but they need to authenticate and be authorized. 

## Implementation description:

The main work is situated in the ` api ` folder. The project is divided in 5 packages: `config`, `db`, `server`, `service`, `token`. 
The main services provided by the system, is to allow users to register, to log in using 2FA with a Time-based OTP provided by an authenticator app,
to store messages in an encrypted format, using an algorithm of choice, and to retrieve all the stored messages. The encryption algorithms a user can use are:
- Rsa 
-	Caesar
-	Caesar with Permutation
-	Playfair
-	Vigener
-	Blowfish
-	One Time Pad

The user upon registering must choose a role for himself. Depending upon his role, he can access only certain ciphers. For example the role `ClassicUser` will
allow the user only to encrypt using the Caesar, Caesar with Permutation, Playfair, and Vigener ciphers. The possible user roles are:
- ClassicUser
- AssymetricUser
- SymmetricUser

### Package db

Here is located all the code related to the data storing. The type of the database is an in memory one, in form of a map which stores users by their ids, users 
by their usernames, their messages by message's id and messages by the messages' owner. The datastore is defined by the 
`Store` interface and is implemented by the `InMemStore` struct:

``` golang
type Store interface {
	StoreMessage(message *Message)
	StoreUser(user *User)
	GetUser(key string) (User, error)
	SetUser(key string, value User) error
	GetMessage(id uuid.UUID) (Message, error)
	GetMessagesOfUser(username string) ([]Message, error)
}
```

``` golang
type InMemStore struct {
	UserById           map[uuid.UUID]*User
	UserByUsername     map[string]User
	MessageById        map[uuid.UUID]*Message
	MessagesByUsername map[string][]Message
}
```

All the corresponding db methods are further implemented:

```golang
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
// (...not all are presented here in the report)
```
The `user` and `message` struct defines what information about a user and about their messages are stored in the database. Each user has an `Id` which is 
actually an uuid, an `Username`, a `Password` which is hashed before storing it in database, a `Choice` (role) which is either a `ClassicUser` or a `AssymetricUser` or a `SymmetricUser`
, and a `TOTPSecret` which a secret key of the user, used for generating Time based One Time Password in an authenticator app, and for validating the OTP
on the backend side.

```golang

type User struct {
	Id         uuid.UUID
	Username   string       `json:"username"`
	Password   string       `json:"password"`
	Choice     CipherChoice `json:"choice"`
	TOTPSecret string
}
```
Also here in `user.go` is located the possible user roles along with the mapping cipher for each role:

```golang
const (
	ClassicUser CipherChoice = iota
	AssymetricUser
	SymmetricUser
)

var CipherRoles = map[CipherChoice][]EncryptionAlg{
	ClassicUser:    {Caesar, CaesarPerm, Playfair, Vigener},
	AssymetricUser: {Rsa},
	SymmetricUser:  {Blowfish, OneTimePad},
}
```

Each message is described by an ID (uuid), by `EncryptedMessage` which is a byte array of the encrypted message, by `EncryptionAlg` which determines which 
algorithm to use for decryption of messages, and by `Author` field which describes to whom the message belongs.

```golang
type Message struct {
	Id               uuid.UUID     `json:"id"`
	EncryptedMessage []byte        `json:"encrypted_message"`
	EncryptionAlg    EncryptionAlg `json:"encryption_alg"`
	Author           string        `json:"author"`
}
```

### Package token

The `token` package is responsible for generating a token after logining in users. This token is used to authenticate logged-in users.
Firstly the interface `TokenMaker` is defined:

```golang

type TokenMaker interface {
	// CreateToken creates a new token for a specific hash with unique email,
	CreateToken(username string,  duration time.Duration) (string, error)

	// VerifyToken checks if the tocken is valid, or not
	VerifyToken(token string) (*Payload, error)

	// AuthentificateToken marks authentitcated field in the token payload as true, after 2fa is succesful,
	AuthenticateToken(payload Payload) (string, error)
}
```
This interface is then implemented by the `PasetoMaker` struct which has a reference to the V2 struct from the `paseto` package, and a []byte of the symmectric
key used to encrypt the token.

```golang
// PasetoMaker is a PASETO token maker which implements the TokenMaker interface
type PasetoMaker struct {
	paseto       *paseto.V2
	symmetricKey []byte
}
```
PASETO is a token similar to JWT, but more secure, used in stateless token-based authentication. There are local(symmetric) PASETOs and public(assymetric) ones.
In this project I used a v2 local PASETO. Local PASETOs are always created and encrypted using a secret key. A PASETO developer library will take JSON data someone wants to securely transmit and encrypt it using the secret key. 
The local PASETO can then be decrypted later using the same secret key used to create it.
The way local PASETOs are created is simple:

   - A secure random function generates a random byte string
   - The blake2b cryptographic hashing algorithm uses the random byte string as input to create a nonce. blake2b was chosen because it is much faster than other cryptographic hashing functions while remaining at least as secure as SHA-3.
   - The PASETO header (v2.local) is combined with the nonce and the footer (if present) to make a pre-authentication string
   - The payload of the token (all the JSON data) is then encrypted using XChaCha20-Poly1305 (authenticated encryption), using the secret key along with the pre-authentication string to ensure the integrity of the PASETO
   - Finally, a token string is created of the form v2.local.payload.optional_footer
 
The token payload is defined in `payload.go` and has a field `Username` to mark to whom  the token belongs, and `Authenticated` to mark if the user
passed the second authentication factor (TOTP).

```golang
// Payload contains the payload data of the token
type Payload struct {
	ID            uuid.UUID `json:"id"`
	Username      string    `json:"username"`
	Authenticated bool      `json:"authenticated"`
	IssuedAt      time.Time `json:"issued_at"`
	ExpiredAt     time.Time `json:"expired_at"`
}
```
After logining in, the user will use the provided token to access the web services, by writing the token in the HTTP header with the 'Authorization' key,
and with the 'bearer' prefix.
Here it is how the `PasetoMaker` implements the `CreateToken()`, `VerifyToken()` and `AuthenticateToken()` methods

This method creates a new payload with the user's username, duration and encrypts it using the Encrypt() method provided by the paseto library in go. The string token is returned and error if it occured.
```golang
// CreateToken creates a new token for a specific hash with unique email,
func (p *PasetoMaker) CreateToken(username string, duration time.Duration) (string, error) {
	payload, err := NewPayload(username,  duration)
	if err != nil {
		return "", err
	}

	return p.paseto.Encrypt(p.symmetricKey, payload, nil)
}
```
This method is used the mark that the user passed the second authentication factor, which is TOTP.
```golang
// AuthentificateToken marks authentitcated field in the token payload as true, after 2fa is succesful,
func (p *PasetoMaker) AuthentificateToken(payload Payload) (string, error) {

	payload.Authenticated = true

	return p.paseto.Encrypt(p.symmetricKey, payload, nil)
}
```

This method checks that the token is valid, wasn't tampered, or changed in a malicious way.
```golang
// VerifyToken checks if the tocken is valid, or not and returns the decrypted payload
func (p *PasetoMaker) VerifyToken(token string) (*Payload, error) {
	payload := &Payload{}

	err := p.paseto.Decrypt(token, p.symmetricKey, payload, nil)
	if err != nil {
		return nil, ErrInvalidToken
	}

	err = payload.Valid()
	if err != nil {
		return nil, err
	}
	return payload, nil
}
```

### Package service
This package implements all the logic of the application. I will not go in depths with the implementation since it is a lot to cover. This is the `Service`
interface that defines all the logic the application implements:
```golang
type Service interface {
	Register(username, password string, choice int) (db.User, *otp.Key, error)
	Login(Username string, password string) (db.User, error)
	CheckTOTP(username, totp string) (db.User, error)
	StoreAndEncryptMessage(username string, message string, encryptAlgorithm int) (db.Message, error)
	GetMessageFromDB(username string, messageID uuid.UUID) (string, error)
	GetMessagesOfUser(username string) ([]string, error)
}
```
It is implemented by the `ServerService` which embeddes `MessageService` and `UserService` each of which is also an interface. 
This `Service` interface is further embedded in a `Server` struct responsible for the api. 

```golang
type ServerService struct {
	MessageService
	UserService
}

func NewServerService(database db.Store) Service {
	return &ServerService{MessageService: NewMessageService(database), UserService: NewUserService(database)}
}

```

The user service is embedding the database. It is responsible for logining in users, for registering them , for checking the Time based OTP.
```golang
type UserService interface {
	Register(username, password string, choice int) (db.User, *otp.Key, error)
	Login(Username string, password string) (db.User, error)
	CheckTOTP(username, totp string) (db.User, error)
}

type userService struct {
	db db.Store
}
```

When the user is registered he is given a QR Code ,and a Secret Key which he can use to set up an Authenticator App, (for example Google Authenticator).
Firstly, the uniqueness of the username is checked, then the password is hashed with a salt using bcrypt algorithm, then a uuid is generated, 
the role choice is validated, and the TOTP secret is finally generated. If all these performed without errors, the user is stored in the database, otherwise the error is returned.
This is how the User is registered:

```golang
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
```

The message service is responsible for encrypting and storing in the db a message, for retrieving from the db a message, and for retrieving all the messages of a user.

```golang
type MessageService interface {
	StoreAndEncryptMessage(username string, message string, encryptAlgorithm int) (db.Message, error)
	GetMessageFromDB(username string, messageID uuid.UUID) (string, error)
	GetMessagesOfUser(username string) ([]string, error)
}

type messageService struct {
	db db.Store
}
```
The `StoreAndEncryptMessage()` method, takes in an username, a message string and encryption algorithm provided by the user. Firsltly the method checks
if the user with such username is present in the database, then the encryption algorithm is validated, then the message is encrypted and stored.
One important thing is that Role Based Access Control (RBAC) autorization is verified here. It is checked if the cipher choice of the user is belonging 
to the cipher role group of the user. An user could not encrypt with RSA if he is a classicUser, for example. He could, in this case, encrypt using only classical ciphers.
```golang
func (m *messageService) StoreAndEncryptMessage(username string, message string, encryptAlgorithm int) (db.Message, error) {
	user, err := m.db.GetUser(username)
	if err != nil {
		return db.Message{}, err
	}

	if encryptAlgorithm < int(db.Rsa) || encryptAlgorithm > int(db.OneTimePad) {
		return db.Message{}, ErrInvalidAlg
	}

	chiperGroup := user.Choice
	isPresent := false
	for _, alg := range db.CipherRoles[chiperGroup] {
		if int(alg) == encryptAlgorithm {
			isPresent = true
		}
	}
	if isPresent == false {
		return db.Message{}, ErrUnauthorisedAlg
	}

	encryptedMessage := encryptMessage(db.EncryptionAlg(encryptAlgorithm), message)
	if encryptedMessage == nil {
		return db.Message{}, ErrEncryption
	}

	messageId, err := uuid.NewRandom()
	if err != nil {
		return db.Message{}, ErrUUID
	}

	dbMessage := db.Message{
		Id:               messageId,
		EncryptedMessage: encryptedMessage,
		EncryptionAlg:    db.EncryptionAlg(encryptAlgorithm),
		Author:           username,
	}
	m.db.StoreMessage(&dbMessage)
	return dbMessage, nil
}
```

### Package server
The server package calls all the service logic in separate handler functions. The endpoints defined by the server are:
```golang
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
```
A middleware is used to check the authentication using the PASETO token before accessing such routes as  `POST /users/twofactor` ,  `POST /message` ,  `GET /message/:id` , ` GET /message/all` . 
The `AuthMiddleware` checks that the authorization header is mandatory provided, checks for the Authorization type to be `Bearer` , verifies the token for integrity and excludes token expiration, 
and checks if the `Authenticated` field of the payload is true (meaning that the user passed two-factor authentication).

```golang
func AuthMiddleware(tokenMaker token.TokenMaker) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		log.Println("Hello")
		authorizationHeader := ctx.GetHeader(authorizationHeaderKey)
		if len(authorizationHeader) == 0 {
			err := errors.New("authorization header is not provided")
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, ErrorResponse(err))
			return
		}

		fields := strings.Fields(authorizationHeader)
		if len(fields) < 2 {
			err := errors.New("invalid authorization header format")
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, ErrorResponse(err))
		}

		authorizationType := strings.ToLower(fields[0])
		if authorizationType != authorizationTypeBearer {
			err := fmt.Errorf("unsupported authorization type %s", authorizationType)
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, ErrorResponse(err))
			return
		}

		accessToken := fields[1]
		payload, err := tokenMaker.VerifyToken(accessToken)
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, ErrorResponse(err))
			return
		}

		if payload.Authenticated == false && ctx.FullPath() != "/users/twofactor" {
			err := fmt.Errorf("not logged in using 2 factor auth")
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, ErrorResponse(err))
			return
		}

		//stored in the gin context with the authorizationPayloadKey
		ctx.Set(authorizationPayloadKey, payload)
		ctx.Next()
	}
}
```
The Gin Web Framework was used for creating the API and implementing HTTP handler functions.

## Application demo:

1.First the user is registering and upon registering he/she indicates the role choice (0 - ClassicUser, 1 - AssymetricUser, 2 -SymmetricUser ):<br />

![image](https://user-images.githubusercontent.com/67596753/207687921-ba064a12-6391-4b01-9523-bb8621302670.png)<br />
2. After registering a response is provided and a QR code that can be used to set up the Authenticator App (Google Authenticator for example, any Authenticator can be used)

![image](https://user-images.githubusercontent.com/67596753/207688320-a7031d3e-769d-4e9f-a416-2373fe9df31e.png)
![image](https://user-images.githubusercontent.com/67596753/207688359-eaa48857-8221-4227-a142-7fe292d8f736.png)<br />
3. After this the user must scan the QR code and set up the authenticator. In my case, I used Google Authenticator.
 
![image](https://user-images.githubusercontent.com/67596753/207694698-69eb7c00-d72b-4bd9-973e-41297df2434b.png)<br />
4. Then the user should log in:
 
![image](https://user-images.githubusercontent.com/67596753/207694965-9b782621-818b-4cfd-9221-6cf85cd81d52.png)<br />
5. The response will contain a PASETO token, but inside, the token is not yet authenticated, because 2FA is not yet passed.
 
![image](https://user-images.githubusercontent.com/67596753/207695362-f6b970ca-370c-4678-bef0-14b31af7a9d6.png)<br />
6. The User must pass second factor authentication by introducing the Time based password from the Authenticator App. Also the user should pass in the PASETO token from the previous stage.

![image](https://user-images.githubusercontent.com/67596753/207697155-706b8a6e-5551-4ddd-8a0d-8901dba42f89.png)
![image](https://user-images.githubusercontent.com/67596753/207697221-3369356f-804b-4c14-91f7-07d95c1abbc6.png)<br />

7. As a response, a new authenticated PASETO token is returned by the server, together with user's uuid.

![image](https://user-images.githubusercontent.com/67596753/207697345-5a095916-eaf2-468a-bc0f-b4e6ae1a3962.png)<br />
8. Then the user can create and encrypt a message, if he is authorized for that choosen cipher.

![image](https://user-images.githubusercontent.com/67596753/207697589-a85fcee0-a2a1-4f0e-b748-4d306457c573.png)<br />
9. The response returned by the serve contains the encrypted message, the uuid of the message, the author and the used cipher:
 
![image](https://user-images.githubusercontent.com/67596753/207697749-20a0262f-ba7f-4ecd-9c1f-a868603f4d9c.png)<br />
10. If for example the user tries to encrypt using the RSA cipher, which he is not authorized to use, the server will return an error message:

![image](https://user-images.githubusercontent.com/67596753/207697949-0f4c5cce-b58e-40ee-97c1-03e6631ea22e.png)<br />
11. The user can request  to see all encrypted messages:

![image](https://user-images.githubusercontent.com/67596753/207702388-adbe4b16-8e2d-42f7-b455-4d70599b79e7.png)<br />
12. Also for security, the token has an expiration limit of 150 minutes.

![image](https://user-images.githubusercontent.com/67596753/207698197-85577d1b-3b8b-491c-ae3c-2be45ee791e2.png)<br />


## Conclusions:
In this laboratory worked I practiced to create an authentication and authorization system that allows logined in users to access certain web services (ciphers).
I learned how to create a second factor authentication system using Time based One Time Password as described in RFC 6238 and
in a Google Authenticator compatible manner.
I learned that when a user loses access to their TOTP device, they would no longer have access to their account. 
Because TOTPs are often configured on mobile devices that can be lost, stolen or damaged, this is a common problem.
Such an application should provide their users "backup codes" or "recovery codes" to escape such situations. I also understood that there are
Role Based Access Control, Attribute Based Access Control and Relationship-Based Access Control autorization systems. In this project, I used a role based one,
which in other words is a collection of permissions a user has. For authentication, I implemented a token based system, which ensures that only authenticated in the system people, have the right to access the app's resourses.
