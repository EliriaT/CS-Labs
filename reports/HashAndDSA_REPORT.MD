#  Topic: Hash functions and Digital Signatures.

### Course: Cryptography & Security
### Author: Tiora Irina

----

## Theory
&ensp;&ensp;&ensp; Hashing is a technique used to compute a new representation of an existing value, message or any piece of text. The new representation is also commonly called a digest of the initial text, and it is a one way function meaning that it should be impossible to retrieve the initial content from the digest.

&ensp;&ensp;&ensp; Such a technique has the following usages:
  * Offering confidentiality when storing passwords,
  * Checking for integrity for some downloaded files or content,
  * Creation of digital signatures, which provides integrity and non-repudiation.

&ensp;&ensp;&ensp; In order to create digital signatures, the initial message or text needs to be hashed to get the digest. After that, the digest is to be encrypted using a public key encryption cipher. Having this, the obtained digital signature can be decrypted with the public key and the hash can be compared with an additional hash computed from the received message to check the integrity of it.


## Examples
1. Argon2
2. BCrypt
3. MD5 (Deprecated due to collisions)
4. RipeMD
5. SHA256 (And other variations of SHA)
6. Whirlpool

## Objectives:

1. Get familiar with the hashing techniques/algorithms.

2. Use an appropriate hashing algorithms to store passwords in a local DB.

3. Use an asymmetric cipher to implement a digital signature process for a user message.


## Implementation description

The hashing implementation is done in the user package that defines a struct for a User:


```golang
type User struct {
	Username string
	Password string
	Message  string
}
```

In the User package also the in-memory database is implemented along with the `UserService` that provides means of registering and loging a user.
The database is described by an interface which defines the implementation of 2 methods on the database, the `Get()` and `Set()` methods. The database is a key-value store.

```golang
type Database interface {
	Get(key string) (User, error)
	Set(key string, value User) error
}
```

The in-memory datastore is represented by an internal map which stores the key of type string along with the mapping value of type `User`. The datastore will store Users.
The struct `inMemDB`  implements the Database interface.

```golang
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
```

The NewStore() function initialises and returns a in-memory datastore. 
```golang
func NewStore() inMemDB {
	return inMemDB{
		dataStore: make(map[string]User),
	}
}
```

`userService` has a compositon relation with the datastore and is implementing the UserService interface. The `Register()` method returns an error if an error occurs
when registering a user and the `Login()` method returns the logged-in user and an error if exists. The `userService` struct implements the interface and has a 
an instance of Database interface, defined earlier.

```golang
type userService struct {
	db Database
}
```

```golang
type UserService interface {
	Register(Username string, password string) error
	Login(Username string, password string) (User, error)
}
```

At registration the password is hashed using the bcrypt algorithm. In the database, the hashed form is saved. If at saving an error occurs, it is returned.

```golang
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
```

```golang
// Returns the bcrypt hash of the password
func HashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("Failed to hash the password")
	}
	return hexutil.Encode(hashedPassword), nil
}
```

At logging, firsly, the presence of a user with such an input username is checked. If it is not present, an error is returned. Then the input password is checked
by comparing it with the hashed version. For this the CompareHashAndPassword() function of the bcrypt package is used.

```golang
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
```

```golang
// Checks if the provided password is correct, nil if correct, error if wrong
func CheckPassword(password string, hashedPassword string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}
```

The message service is defined by the `MessageService` interface. It defines `GetMessageFromUser()`, `SignMessage()`, and `VerifyMessage()` methods.
The `GetMessageFromUser()` is used to get an input message from the user.

```golang
type MessageService interface {
	GetMessageFromUser(loggedUser *user.User)
	SignMessage(msg string) ([]byte, []byte, error)
	VerifyMessage(hashedMessage, signature []byte) error
}
```

The interface is then implemented by the `messageService` struct which has a privateKey attribute of type privateKey from the Elliptic Curve Digital
Signature Algorithm package.
In the `Sign()` method, the message is first hashed using Keccak-256 algorithm. Then it is signed by calculating an ECDSA signature. The `signature` and `hashedMessage`
is then returned along with a nil error if no error occured.

```golang
func (m messageService) SignMessage(message string) ([]byte, []byte, error) {
	//Keccak-256 as the hashing algorithm
	hash := crypto.Keccak256Hash([]byte(message))
	signature, err := crypto.Sign(hash.Bytes(), m.privateKey)
	if err != nil {
		return nil, nil, err
	}
	return signature, hash.Bytes(), nil
}
```

In the `VerifyMessage()` the signature is checked by comparing the public key obtained from the signature using `Ecrecover()` function from the crypto package.
If the retrieved public key and original public key are equal, the signature is considered value and nil is returned, else an error is returned.

```golang
func (m messageService) VerifyMessage(hashedMessage, signature []byte) error {
	publicKey := m.privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("error casting public key to ECDSA")
	}

	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)
	// Ecrecover (elliptic curve signature recover) from the go-ethereum crypto package to retrieve the public key of the signer.
	sigPublicKey, err := crypto.Ecrecover(hashedMessage, signature)
	if err != nil {
		log.Fatal(err)
	}
	// Comparing the signature's public key with the expected public key and if they match then the expected public key holder is indeed the signer of the original message
	matches := bytes.Equal(sigPublicKey, publicKeyBytes)
	if !matches {
		return fmt.Errorf("Signature is not valid!!")
	}
	return nil
}
```
The constructor `NewMessageService()` returns an instance of the `MessageService` interface and initialises the private key.

```golang
func NewMessageService() MessageService {
	privateKey, err := crypto.HexToECDSA("fad9c8855b740a0b7ed4c221dbad0f33a83a49cad6b3fe8d5817ac83d38b6a19")
	if err != nil {
		log.Fatal(err)
	}
	return messageService{
		privateKey: privateKey,
	}
}
```

## Client

The client in `main.go` creates a `userService` by injecting a datastore in the constructor. Then it is registering, logining-in, and for testing purpose,
the saved password in the database is printed. Then the user is prompted to type a message in the terminal and the message is signed and verified.

```golang
func main() {
	rand.Seed(time.Now().UnixNano())

	userService := user.NewUserService(user.NewStore())

	// Registering a user
	err := userService.Register("irina", "averysecretpasswordandnoonecanfinditofcourse")
	if err != nil {
		log.Fatal("Something went wrong: ", err.Error())
	}

	// Logining the user. Inside, the password is checked by comparing with its stored hash
	loggedUser, err := userService.Login("irina", "averysecretpasswordandnoonecanfinditofcourse")
	if err != nil {
		log.Fatal("Something went wrong: ", err.Error())
	}

	// Representing the hash form of the password
	hashedPassword := loggedUser.Password
	fmt.Println("The hashed password of the user is: ", hashedPassword)

	// Getting an input message of the user from the terminal
	messageService := message.NewMessageService()
	messageService.GetMessageFromUser(&loggedUser)

	// Signing the message and getting back the signature and the hashedMessage
	signature, hashedBytesMessage, err := messageService.SignMessage(loggedUser.Message)
	if err != nil {
		log.Fatal("Something went wrong: ", err.Error())
	}

	// Checking the signature
	err = messageService.VerifyMessage(hashedBytesMessage, signature)
	if err != nil {
		log.Fatal("Message is not valid! ")
	}
	log.Println("The signature is valid. ")

}
```
 
## Program results:
![image](https://i.postimg.cc/brj0CNPK/Screenshot-from-2022-11-11-21-43-57.png)


## Conclusions / Screenshots / Results

In this laboratory work I learned how to use a Digital Signing algorithm for guaranteeing integrity and non-repudiation of a message to a system. I used 
the Elliptic Curve Digital Signature Algorithm, as defined in FIPS 186-4 and SEC 1, Version 2.0. I also learned more about hashing and its use cases. I learned 
that it can be used together with the Digital Signature algorithms for security enhancement. I get to know what salting and that it is used to protect
against duplicate or common passwords being identifiable, as well as to give more randomness to a hash function.
