#  Asymmetric Ciphers.

### Course: Cryptography & Security
### Author: Tiora Irina

----

## Theory
&ensp;&ensp;&ensp; Asymmetric Cryptography (a.k.a. Public-Key Cryptography) deals with the encryption of plain text when having 2 keys, one being public and the other one private. The keys form a pair and despite being different they are related.

&ensp;&ensp;&ensp; As the name implies, the public key is available to the public but the private one is available only to the authenticated recipients. 

&ensp;&ensp;&ensp; A popular use case of the asymmetric encryption is in SSL/TLS certificates along side symmetric encryption mechanisms. It is necessary to use both types of encryption because asymmetric ciphers are computationally expensive, so these are usually used for the communication initiation and key exchange, or sometimes called handshake. The messages after that are encrypted with symmetric ciphers.


## Examples
1. RSA
2. Diffie-Helman
3. ECC
4. El Gamal
5. DSA

## Objectives:

1. Get familiar with the asymmetric cryptography mechanisms.

2. Implement an example of an asymmetric cipher.

3. Use a client class or test classes to showcase the execution of your programs.


## Implementation description

RSA (Rivest–Shamir–Adleman) algorithm is an asymmetric cryptography algorithm. Asymmetricy means that there are two keys, Public Key and Private Key. The Public Key is given to everyone and the Private key is kept private.

The idea of RSA is based on the fact that it is difficult to factorize a large integer. The public key consists of two numbers where one number is a multiplication of two large prime numbers. And private key is also derived from the same two prime numbers. So if somebody can factorize the large number, the private key is compromised. Therefore encryption strength totally lies on the key size and if we double or triple the key size, the strength of encryption increases exponentially. RSA keys can be typically 1024 or 2048 bits long.

The RSA struct implements the cipher interface which defines the Encrypt() and Decrypt() methods as well as Name() for returning struct's name. The implementation of the RSA algorithm is located inside the `rsa` package(and folder). The methods Encrypt(), Decrypt() and Name() are public, visible outside the package, inside the main package used as a client for testing the algorithm.

```golang
type Cipher interface {
	Encrypt(src []byte) ([]int64, error)
	Decrypt(src []int64) ([]byte, error)
	Name() string
}
```

The RSA struct *embeds* a PrivateKey struct and a Public Key struct. 

```golang
type RSA struct {
	PrivateKey
	PublicKey
}
```

Similarly, a PrivateKey struct *embeds* a PublicKey struct, because it requires some data from the public key such as `N` and `phi`, in order to compute the secret key.

```golang
type PrivateKey struct {
	PublicKey       // public part.
	d         int64 // private exponent
}
```

Struct Embedding in golang is a form of composition, when a struct may *contain* another struct. 
The `PublicKey` struct has such attributes as `N`, `E` and `phi`. `N` and `E` form the public key pair available to all people interested to encrypt a message and send it privately. The `phi` is a private attribute (because it starts with a small letter), and is used to calculate `E`, as well as used in the PrivateKey struct to calculate the private key `d`.


```golang
type PublicKey struct {
	N   int64 // modulus
	E   int64 // public exponent
	phi int64
}
```
The `PublicKey` has a method `setPublicKey` which selects randomly two distinct prime numbers, `p` and `q`, from a list of determined prime numbers, located in `primes.go`. For security enhancement, this list should be as large as possible, kept encrypted and in privacy, and the primes should be as large as possible. For simulation purpose, I used a list of relatively small prime numbers.

```golang
func (pk *PublicKey) setPublicKey() {

	lenPrimes := len(Primes)
	pInd := rand.Intn(lenPrimes)
	qInd := rand.Intn(lenPrimes)
	for qInd == pInd {
		qInd = rand.Intn(lenPrimes)
	}
	p := Primes[pInd]
	q := Primes[qInd]

```

The next step is to compute the public key pair `(N,E)`. Also `phi` function is calculated as the product of `phi = (p - 1) * (q - 1)` . `N` is `N = p * q`, and `E` should be `E>1` and `E<phi`, and it should be coprime with `phi` and `N`. For ensuring that they are coprimes, I used a simple function named `gcd` for calculating the greatest commmon divisor of two numbers. Two numbers are coprime when their greatest common divisor is 1. Thus in this case, 
`gcd(E, phi) == 1 && gcd(E, N) == 1` .

```golang
	pk.N = int64(p) * int64(q)
	pk.E = 2
	pk.phi = (int64(p) - 1) * (int64(q) - 1)
	for pk.E < pk.phi {
		// e must be co-prime to phi and smaller than phi.
		if gcd(pk.E, pk.phi) == 1 && gcd(pk.E, pk.N) == 1 {
			break
		} else {
			pk.E++
		}
   }
}
```

The `PrivateKey` struct embeds the `PublicKey` struct in order to have access to previously calculated `E` and `phi`. The secret key `d` is calculated such that it represents the modular multiplicative inverse of `e mod phi`. In other words, `e * d mod phi = 1`. For finding the multiplicative inverse the `modInverse` function is used. Here it is how the private key is set:

```golang
func (pk *PrivateKey) setPrKey(publicKey PublicKey) error {
	pk.PublicKey = publicKey

	//d is modular inverse of e mod phi
	pk.d = modInverse(pk.E, pk.phi)
	if pk.d == 0 {
		return fmt.Errorf("Can not set private key.")
	}
	return nil
}
```

The `modInverse` function iterates till phi, and checks each possible candidate to satisfy the requirements. Another possible solution to find the modular multiplicative inverse is to calculate it using Extended Euclidean algorithm.
```golang
func modInverse(a int64, m int64) int64 {
	var x int64
	for x = 1; x < m; x++ {
		if (a%m)*(x%m)%m == 1 {
			return x
		}
	}
	return 0
}
```
The RSA struct implements the `Encrypt(src []byte) ([]int64, error)` and `Decrypt(src []int64) ([]byte, error)` methods of the Cipher interface.  The encryption is done using the public key pair `(E,N)` and the formula:  $$m^e mod N $$  The decryption is done using the private key `d`, and public `N`:
$$m^d mod N $$  

```golang
func (r RSA) Encrypt(src []byte) ([]int64, error) {
	var encNums []int64
	for _, b := range src {
		encMessage := new(big.Int).SetBytes([]byte{b})
		encMessage = encMessage.Exp(encMessage, new(big.Int).SetInt64(r.E), new(big.Int).SetInt64(r.N))
		encNums = append(encNums, encMessage.Int64())
	}

	return encNums, nil
}
func (r RSA) Decrypt(src []int64) ([]byte, error) {

	var decBytes []byte
	for _, b := range src {
		decMessage := new(big.Int).SetInt64(b)
		decMessage = decMessage.Exp(decMessage, new(big.Int).SetInt64(r.d), new(big.Int).SetInt64(r.N))
		decBytes = append(decBytes, decMessage.Bytes()[0])
	}
	return decBytes, nil
}
```
The Encrypt method receives a list of bytes. Firstly a string message m is transformed to a list of bytes on the client side.

```golang
Message := []byte("i am irina.")
```

Encryption of a message is done byte by byte. Each byte is encrypted separetely, and the ecrypted byte takes form of an integer. Each encrypted integer is appended to the `encNums` list of `int64`. The final list of encrypted bytes is returned. Each encrypted num from the `encNums` list maps one to one to the initial byte. 
The decryption is done similary. `src`  is a list of encrypted numbers given as input to the `Decrypt` method. Each number from the `src` is decrypted in the loop, using the previously mentioned formula and appended to the `decBytes`. The client then converts the decrypted list of bytes to the string format:
`string(decryptedMessage)` . The Exp() method from `big.Int` built-in package is used to calculate fast  `a ** b mod m` .

Lastly, there is the `NewRSA()` function which returns an RSA instance and calls the `setPublicKey()` and `setPrKey()` functions. 
```golang
// NewRSA creates and returns a RSA cipher.
func NewRSA() (RSA, error) {
	var cipher RSA
	cipher.setPublicKey()
	cipher.setPrKey(cipher.PublicKey)
	return cipher, nil
}
```


The client represented by the main.go, tests the implementation by creating a list of objects of the Cipher interface type. It calls the `rsa.NewRSA()` function and appends the `rsaCipher` to the list. Then it calls the Encrypt() and Decrypt() methods of the instance.

```golang
//The list composed of objects that correspond to the Cipher interface
	cipherList := make([]cipherInterface.Cipher, 0)

	rsaCipher, _ := rsa.NewRSA()

	cipherList = append(cipherList, rsaCipher)

	//message: "iamirina"
	Message := []byte("i am irina.")

	for i, cipher := range cipherList {
		fmt.Println(i+1, ") ", " Message: ", string(Message), ". Encrypted using: ", cipher.Name())
		encryptedMessage, _ := cipher.Encrypt(Message)
		fmt.Println("The encrypted message: ", encryptedMessage)
		decryptedMessage, _ := cipher.Decrypt(encryptedMessage)
		fmt.Println("The decrypted message: ", string(decryptedMessage))
	}
```

## Program results:
![image](https://i.postimg.cc/yxk7VnDq/Screenshot-from-2022-11-02-12-31-49.png)




## Conclusions / Screenshots / Results

In this laboratory work I learned about how to implement the asymmetric RSA algorithm. I understood that the security of the algorithm relies on the fact that factorizing a large integer mathematicaly is an infeasible (very difficult) task. This algorithm is not suitable for encryption and decryption of large amounts of data, because it is slow. It is used for key exchange in symmetric cryptography in such algorithms as AES.

