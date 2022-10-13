# Symmetric Ciphers. Stream Ciphers. Block Ciphers.

### Course: Cryptography & Security
### Author: Tiora Irina

----

## Theory
&ensp;&ensp;&ensp; Symmetric Cryptography deals with the encryption of plain text when having only one encryption key which needs to remain private. Based on the way the plain text is processed/encrypted there are 2 types of ciphers:
- Stream ciphers:
    - The encryption is done one byte at a time.
    - Stream ciphers use confusion to hide the plain text.
    - Make use of substitution techniques to modify the plain text.
    - The implementation is fairly complex.
    - The execution is fast.
- Block ciphers:
    - The encryption is done one block of plain text at a time.
    - Block ciphers use confusion and diffusion to hide the plain text.
    - Make use of transposition techniques to modify the plain text.
    - The implementation is simpler relative to the stream ciphers.
    - The execution is slow compared to the stream ciphers.

&ensp;&ensp;&ensp; Some examples of stream ciphers are the following:
- Grain: ...
- HC-256: ...
- PANAMA: ...
- Rabbit: ...
- Rivest Cipher (RC4): It uses 64 or 128-bit long keys. It is used in TLS/SSL and IEEE 802.11 WLAN.
- Salsa20: ...
- Software-optimized Encryption Algorithm (SEAL): ...
- Scream: ...

&ensp;&ensp;&ensp; The block ciphers may differ in the block size which is a parameter that might be implementation specific. Here are some examples of such ciphers:
- 3DES
- Advanced Encryption Standard (AES): A cipher with 128-bit block length which uses 128, 192 or 256-bit symmetric key.
- Blowfish: ...
- Data Encryption Standard (DES): A 56-bit symmetric key cipher.
- Serpent: ...
- Twofish: A standard that uses Feistel networks. It uses blocks of 128 bits with key sizes from 128-bit to 256-bit.


## Objectives:

1. Get familiar with the symmetric cryptography, stream and block ciphers.

2. Implement an example of a stream cipher.

3. Implement an example of a block cipher.

4. The implementation should, ideally follow the abstraction/contract/interface used in the previous laboratory work.

5. Use packages/directories to logically split the files that you will have.

6. As in the previous task, please use a client class or test classes to showcase the execution of your programs.


## Implementation description

## 1. General notes
Each implementation is contained inside a struct definition (like a class). Each implementation implements the cipher interface with defines the Encrypt() and Decrypt() methods as well as Name() for returning struct's name. The implementations are located inside a `implementations` package. The methods Encrypt(), Decrypt() and Name() are public, visible outside the package, inside the main package, because they start with the capital letter. The private identifiers start with non-capital letter in golang. 

```golang
type Cipher interface {
	Encrypt(text string) string
	Decrypt(text string) string
	Name() string
}
```
In golang, structs implement interfaces implicitly.
Each struct is associated with a function `Make_class_name_*`, which creates and returns an instance of that struct. This is done to simulate the constructor in golang. For Example: 

```golang
// acts like a constructor
// NewBlowfish creates and returns a  Blowfish cipher.
// The key argument should be the Blowfish key, from 4 to 56 bytes.
func NewBlowfish(key []byte) (*Blowfish, error) {
	var result Blowfish
	if k := len(key); k < 1 || k > 56 {
		return nil, KeySizeError(k)
	}
	initCipher(&result)
	ExpandKey(key, &result)
	return &result, nil
}
```

In main.go, there is a loop that iterates through a list of objects of the Cipher interface type. Then just the Encrypt() and Decrypt() methods of the struct are called.

```golang
Message := []byte{0x69, 0x61, 0x6d, 0x69, 0x72, 0x69, 0x6e, 0x61}

	for i, cipher := range cipherList {
		fmt.Println(i+1, ") ", "Encrypted using: ", cipher.Name())
		encryptedMessage, _ := cipher.Encrypt(Message)
		fmt.Println("The encrypted message: ", base64.StdEncoding.EncodeToString(encryptedMessage))
		decryptedMessage, _ := cipher.Decrypt(encryptedMessage)
		fmt.Println("The decrypted message: ", string(decryptedMessage))
	}
```

## 2. Blowfish cipher

BlowFish algorithm  is a block cipher algorithm and a symmetric cryptography algorithm. The input size of the block is 64 bits and the key size is variable, making it more secure (32-448 bits). It is very fast, it takes less memory, and simple to understand. First we have to generate key.
Firstly, keys are stored in an array of n blocks, n>=1, n<=14 and each block is of 32 bits. In total we can have a max size of the key of 448 bits(32\*14). Basically the key size should be a multiple of 32.
The second step is to initialise an array p, composed of 18 words ( blocks), each block being of length 32 bits[p1,p2...p18]
The fird step is to initialise the S-boxes. We have to initialise 4 subtitution boxes. Each box will have 256 bits [s0,s1...s255]
Then each element of the p array and s boxes is assigned a hexadecimal value.
The p array and s boxes are defined in the ` blowfishConstants.go ` file.
Then the xor operation is performed. For each pi: p<sub>i</sub>=p<sub>i</sub> ⊕ k<sub>i</sub>

This is done in the ` ExpandKey` function.
```golang
func ExpandKey(key []byte, c *Blowfish) {
	j := 0
	for i := 0; i < 18; i++ {
		// Using inlined getNextWord for performance.
		var d uint32
		for k := 0; k < 4; k++ {
			d = d<<8 | uint32(key[j])
			j++
			if j >= len(key) {
				j = 0
			}
		}
		c.p[i] ^= d
	}

```
And the initialisation is done  when the cipher object is created:

```golang
func NewBlowfish(key []byte) (*Blowfish, error) {
	var result Blowfish
	if k := len(key); k < 1 || k > 56 {
		return nil, KeySizeError(k)
	}
	initCipher(&result)
	ExpandKey(key, &result)
	return &result, nil
}

func initCipher(c *Blowfish) {
	copy(c.p[0:], p[0:])
	copy(c.s0[0:], s0[0:])
	copy(c.s1[0:], s1[0:])
	copy(c.s2[0:], s2[0:])
	copy(c.s3[0:], s3[0:])
}
```

Then the data encryption can take place. The plain text is divided in two halves, each of 32 bit size. The first half is xored with p1. The output is sent to an F function. The output of the function is xored with the second half. These actions result in two results after the xor operation. The last xor output is the again xored with p2 and similarly then send to the f function. And then the output of the F function is xored with the output of the first xor from the previous round. The proccess is described in the following image: 
![image](https://i.imgur.com/M5NyFQ7.jpg)


In total we have 18 rounds for each p. The 2 halves of the last round are combined, resulting in the cipher text of 64 bits.
Inside the F function , the 32 bits half is divided in 4 halves each of 8 bits. The operations can be easier understood from the following image: 

![image](https://media.geeksforgeeks.org/wp-content/uploads/20190929212325/F-blowfish.jpg)

The decryption is made in same way, using the same key. The key must be kept secret between the parties.

## 4. One Time Pad Stream Cipher
In cryptography, a one-time pad is a system in which a randomly generated private key is used only once to encrypt a message that is then decrypted by the receiver using a matching one-time pad and key. It is a stream cipher. A one-time pad requires that the key length be at least as long or longer than the message being sent. Messages encrypted with keys based on randomness have the advantage that there is theoretically no way to break the code by analyzing a succession of messages. Each encryption is unique and bears no relation to the next encryption, making it impossible to detect a pattern. But with a one-time pad, the decrypting party must have access to the same key used to encrypt the message; this raises the issue of how to get the key to the decrypting party safely, or how to keep both keys secure.
Typically, a one-time pad is created by generating a string of characters or numbers that will be at least as long as the longest message that will be sent. This string of values is generated in some random fashion, such as by using a computer program with a random number generator. The values are written down on a pad or on any device that someone can read. The pads are given to anyone who is likely to send or receive a sensitive message. Typically, a pad may be issued as a collection of keys -- one for each day in a month, for example, with one key expiring at the end of each day or after it has been used once.

When a message is to be sent, the sender uses the secret key to encrypt each character one at a time. If a computer is used, each bit in the character -- which is usually eight bits in length -- is exclusively OR'ed with the corresponding bit in the secret key. With a one-time pad, the encryption algorithm is simply the XOR operation. Although a one-time pad is truly the only unbreakable encryption method, its use is impractical for many modern applications because the system must meet the following conditions:

 1.   The key must be the same size as the message being sent.
 2.   The key must be truly random.
 3.   Keys must never be reused.
 4.   Keys must be securely shared between the sending and receiving parties.



```
For encryption and decryption a simple formula is used, with the difference in the operand. When we encrypt we add the key letter with the plaintext letter, when we decrypt we substract Then the modular operation is done. 
```golang
cipherText := (plainText + secretKey) % 255
		result[i] = byte(cipherText)
plainText := (cipherText - secretKey) % 255
		if plainText < 0 {
			plainText += 255
		}
```
The encryption and decryption is done in a stream, byte by byte. In this implementation an initial slice of random bits is used to creat the random key pad. This pad consists of n pages. We set the number of pages and the  initial page we start from. For a single message , a single same page is used for encryption and decryption. If we want to encrypt another message, the used must call the `NextPage()` message. Here it is how the pad and pages in  the pad are formed:
```golang
func NewPad(material []byte, pageSize int, startPage int) (*Pad, error) {
	// A zero-length page would cause this routine to loop infinitely
	if pageSize < 1 {
		return nil, fmt.Errorf("otp: page length must be greater than 0")
	}

	if len(material) < pageSize {
		return nil, fmt.Errorf("otp: page size too large for pad material")
	}

	// Do the page-splitting work up front
	var pages [][]byte
	for i := 0; i+pageSize <= len(material); i += pageSize {
		pages = append(pages, material[i:i+pageSize])
	}

	// Create the new OTP pad
	p := Pad{
		pages:       pages,
		currentPage: startPage,
	}

	// Set the page index in the new pad
	if err := p.SetPage(startPage); err != nil {
		return nil, err
	}

	return &p, nil
}
```

The One Time Pad object is an instance of the following struct, having the list of pages and the pointer to the current page:
```golang
type Pad struct {
	pages       [][]byte
	currentPage int
}
```

## Conclusions / Screenshots / Results

In this laboratory work i learned more profoundly how stream and block ciphers work. I studied blowfish cipher, its advantages and disadvantages and the same for the one time pad. I learned that one time pad is very secure in theory, but hard to implement in practice, in modern systems, because it requires high security of the key. It has two vulnerabilities: the key is long as the message, and secondly that the one time pad encryption scheme is only secure, if a particular key is used to encrypt only a single plain text. I learned about the blowfish ciphers and why it is more secure than the other block ciphers - because it has a variable length of the key, thus making it harder to brute force attack it. I learned that this cipher should only be used where compatibility with legacy systems, not security, is the goal. It is faster and much better than DES Encryption but still it can be vulnerable to birthday attacks.

## Program results:
![image](https://i.postimg.cc/nr70FTxm/Screenshot-from-2022-10-13-13-58-38.png)
