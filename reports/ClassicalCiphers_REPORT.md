# Intro to Cryptography. Classical ciphers. Caesar cipher.

### Course: Cryptography & Security
### Author: Tiora Irina

----

## Theory
&ensp;&ensp;&ensp; Cryptography consists a part of the science known as Cryptology. The other part is Cryptanalysis. There are a lot of different algorithms/mechanisms used in Cryptography, but in the scope of these laboratory works the students need to get familiar with some examples of each kind.

&ensp;&ensp;&ensp; First, it is important to understand the basics so for the first task students will need to implement a classical and relatively simple cipher. This would be the Caesar cipher which uses substitution to encrypt a message. 

&ensp;&ensp;&ensp; In it's simplest form, the cipher has a key which is used to substitute the characters with the next ones, by the order number in a pre-established alphabet. Mathematically it would be expressed as follows:

$em = enc_{k}(x) = x + k (mod \; n),$

$dm = dec_{k}(x) = x + k (mod \; n),$ 

where:
- em: the encrypted message,
- dm: the decrypted message (i.e. the original one),
- x: input,
- k: key,
- n: size of the alphabet.

&ensp;&ensp;&ensp; Judging by the encryption mechanism one can conclude that this cipher is pretty easy to break. In fact, a brute force attack would have __*O(nm)*__ complexity, where __*n*__ would be the size of the alphabet and __*m*__ the size of the message. This is why there were other variations of this cipher, which are supposed to make the cryptanalysis more complex.

An improvement to the Caesar Cypher is to try permute the alphabet before tranposing it with a key. In such way, the encrypted text is more random, and harder to decrypt, because now there are at least 26! keys. But still Caesar cipher with a permuted alphabet is vulnerable to frequency analysis, because it is a monoalphabetic cipher. It can be broken simply by annalyzing the most frequent letters in the encrypted text.

Vigenere cypher is an improvement of the last two, because it is a polyalphabetic cypher. It uses two letters to generete the encrypted letter. It makes use of a key, and then the key is repeated till the length of the plaintext. The encrypted letter is the result of summing the letter of the key at position i, plus the the letter of plaintext at position i modulo 26.

Playfair cypher is a digraph substitution which encrypts digraphs in each iteration, instead of single letters.It initially creates a key-table of 5 * 5 matrix. The matrix contains alphabets that act as the key for encryption of the plaintext. Note that any alphabet should not be repeated. Another point to note that there are 26 alphabets and we have only 25 blocks to put a letter inside it. Therefore, one letter is excess so, a letter will be omitted (usually J) from the matrix. Nevertheless, the plaintext contains J, then J is replaced by I. It means treat I and J as the same letter, accordingly.


## Objectives:

1. To get familiar with the basics of cryptography and classical ciphers.

2. To implement 4 types of the classical ciphers:
    - Caesar cipher with one key used for substitution (as explained above),
    - Caesar cipher with one key used for substitution, and a permutation of the alphabet,
    - Vigenere cipher,
    - Playfair cipher.


3. To structure the project in methods/classes/packages as neeeded.

## Implementation description

## 1. General notes
Each implementation is contained inside a struct definition (like a class), and has a key attribute which can either be a string or an int depending of the algorithm itself. Each implementation implements the cipher interface with defines the Encrypt() and Decrypt() methods as well as Name() for returning struct's name. The implementations are located inside a `implementations` package. The methods Encrypt(), Decrypt() and Name() are public, visible outside the package, inside the main package, because they start with the capital letter. The private identifiers start with non-capital letter in golang. 

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
func MakeCaesarCipher() CaesarCipher {
	return CaesarCipher{alphabet: []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ")}
}
```

In main.go, there is a loop that iterates through a list of objects of the Cipher interface type. Then just the Encrypt() and Decrypt() methods of the struct are called.

```golang
for i, cipher := range cipherList {
		fmt.Println(i+1, ") ", "Encrypted using: ", cipher.Name())
		encryptedMessage := cipher.Encrypt("Hi. This message is veeeryyy secret")
		fmt.Println("The encrypted message: ", encryptedMessage)
		decryptedMessage := cipher.Decrypt(encryptedMessage)
		fmt.Println("The decrypted message: ", decryptedMessage)
	}
```

## 2. Caesar cipher

This struct uses the same function for encryption and decryption. The only difference is that for decryption, the -key is passed as an argument.

```
func (c CaesarCipher) Encrypt(text string) string {
	return convertText(text, c.key, c.alphabet)
}
func (c CaesarCipher) Decrypt(text string) string {
	return convertText(text, -c.key, c.alphabet)
}
```
In this algorithm each letter of the plaintext is encrypted according to a formula, taking intro consideration the shift in the alphabet. The formula is simple:

```golang
if char >= 'A' && char <= 'Z' {
			letter := char + s - 'A'
			ind := (letter%26 + 26) % 26
			runesText[i] = alpha[ind]
		}
```

## 3. Caesar cipher with permutation of the alphabet

The key difference here from the simple Caesar cipher is that we shuffle the letters:
```golang
func MakeCaesarPermutationCipher() CaesarPermutationCipher {
	alphabet := []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	rand.Shuffle(len(alphabet), func(i, j int) {
		alphabet[i], alphabet[j] = alphabet[j], alphabet[i]
	})

	return CaesarPermutationCipher{alphabet: alphabet}
}
```
And the decryption algorithm is a little bit different,because we have to take into account the shuffled alphabet as well as the key shift.
```golang
idx := slices.IndexFunc(c.alphabet, func(c rune) bool { return c == char })
			letter := rune(idx) + s
			ind := (letter%26 + 26) % 26
			runesText[i] = ind + 'A'
```
## 4. Vigenere cipher
In this cipher it is needed to clean the plaintext of all whitespaces. As a result only the capital letters remain in the plaintext.

```golang
func cleanString(in string) string {
	out := []rune{}
	for _, v := range in {
		if 65 <= v && v <= 90 {
			out = append(out, v)
		} else if 97 <= v && v <= 122 {
			out = append(out, v-32)
		}
	}

	return string(out)
}
```
For encryption and decryption a simple formula is used, with the difference in the operand. When we encrypt we add the key letter with the plaintext letter, when we decrypt we substract. 
```golang
func (v VigenereCipher) encodeChar(a, b rune) rune {
	return (((a - 'A') + (b - 'A')) % 26) + 'A'
}
func (v VigenereCipher) decodeChar(a, b rune) rune {
	return ((((a - 'A') - (b - 'A')) + 26) % 26) + 'A'
}
```
The encryption and decryption is done letter by letter.

## 5. Playfair cipher

Playfair cipher is a more complex one in terms of implementation. First of all we have to clean the string with the `cleanString()` function. We replace all `J` with `I` in the key. Then we have to generate the cipher table (key table), in such way that the letters are repeated only once. For this we concatenate the key with the alphabet, and then copy only the unique values in the table.

```golang
keyString := p.key + "ABCDEFGHIKLMNOPQRSTUVWXYZ"

	for k := 0; k < len(keyString); k++ {
		repeat := false
		used := false
		for i := 0; i < 5; i++ {
			for j := 0; j < 5; j++ {
				if p.table[i][j] == string(keyString[k]) {
					repeat = true
				} else if p.table[i][j] == "" && !repeat && !used {
					p.table[i][j] = "" + string(keyString[k])
					used = true
				}
			}
		}
	}
}
```
Then the plaintext is divided intro digraphs, in such way that no two letters are the same and X is added where neccessary.
```golang
	for i := 0; i < (length - 1); i++ {

		if text[2*i] == text[2*i+1] {
			text = text[:2*i+1] + "X" + text[2*i+1:]

			length = len(text)/2 + len(text)%2
		}
	}

	digraph := make([]string, length, length)

	for j := 0; j < length; j++ {
		if (j == length-1) && (len(text)/2 == length-1) {
			text = text + "X"
		}
		digraph[j] = string(text[2*j]) + string(text[2*j+1])
	}
```
Then each digraph is encrypted according the encoded digraphs. The decryption procedure is the same as encryption but the steps are applied in reverse order. 

## Conclusions / Screenshots / Results

Classical Cyphers were an important step in the development of the cryptography. It provided means for securing communication in the past. Nowadays they are considered not secure, because they can be broken by brute force or such means as frequency analysis. Here are the results obtained in this laboratory work:


![image](https://user-images.githubusercontent.com/67596753/193137728-a7c2b8a5-9abb-4e56-acf7-bf0c1b68ecb3.png)

