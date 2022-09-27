package implementations

import (
	"fmt"
	"golang.org/x/exp/slices"
	"math/rand"
)

type CaesarPermutationCipher struct {
	key      int
	alphabet []rune
}

func (c *CaesarPermutationCipher) SetKey(a int) {
	c.key = a
}
func (c CaesarPermutationCipher) Encrypt(text string) string {
	s := rune(c.key)
	runesText := []rune(text)
	for i, char := range runesText {
		if char >= 'A' && char <= 'Z' {
			letter := char + s - 'A'
			ind := (letter%26 + 26) % 26
			runesText[i] = c.alphabet[ind]
		} else if char >= 'a' && char <= 'z' {
			letter := char + s - 'a'
			ind := (letter%26 + 26) % 26
			//-A fiindca alphabetul e din litere mari
			runesText[i] = c.alphabet[ind] - 'A' + 'a'
		}
	}
	return string(runesText)
}
func (c CaesarPermutationCipher) Decrypt(text string) string {
	s := rune(c.key)
	runesText := []rune(text)
	for i, char := range runesText {
		if char >= 'A' && char <= 'Z' {
			idx := slices.IndexFunc(c.alphabet, func(c rune) bool { return c == char })
			letter := rune(idx) + s
			ind := (letter%26 + 26) % 26
			runesText[i] = ind + 'A'
		} else if char >= 'a' && char <= 'z' {
			idx := slices.IndexFunc(c.alphabet, func(c rune) bool { return c == (char - 32) })
			letter := rune(idx) + s
			ind := (letter%26 + 26) % 26
			runesText[i] = ind + 'a'
		}
	}
	return string(runesText)
}

// acts like a constructor
func MakeCaesarPermutationCipher() CaesarPermutationCipher {
	alphabet := []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	rand.Shuffle(len(alphabet), func(i, j int) {
		alphabet[i], alphabet[j] = alphabet[j], alphabet[i]
	})
	fmt.Println(string(alphabet))
	return CaesarPermutationCipher{alphabet: alphabet}
}
