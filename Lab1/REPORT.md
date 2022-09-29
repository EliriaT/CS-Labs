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

Playfair cypher is a digraph substitution which encrypts digraphs, in each iteration


## Objectives:

1. To get familiar with the basics of cryptography and classical ciphers.

2. To implement 4 types of the classical ciphers:
    - Caesar cipher with one key used for substitution (as explained above),
    - Caesar cipher with one key used for substitution, and a permutation of the alphabet,
    - Vigenere cipher,
    - Playfair cipher.


3. To structure the project in methods/classes/packages as neeeded.

## Implementation description

* About 2-3 sentences to explain each piece of the implementation.


* Code snippets from your files.

```
public static void main() 
{

}
```

* If needed, screenshots.


## Conclusions / Screenshots / Results

