package implementations

type CaesarCipher struct {
	key      int
	alphabet []rune
}

func (c *CaesarCipher) SetKey(a int) {
	c.key = a
}
func (c CaesarCipher) Encrypt(text string) string {
	return convertText(text, c.key, c.alphabet)
}
func (c CaesarCipher) Decrypt(text string) string {
	return convertText(text, -c.key, c.alphabet)
}

func convertText(text string, key int, alpha []rune) string {

	s := rune(key)
	runesText := []rune(text)
	for i, char := range runesText {
		if char >= 'A' && char <= 'Z' {
			letter := char + s - 'A'
			ind := (letter%26 + 26) % 26
			runesText[i] = alpha[ind]
		} else if char >= 'a' && char <= 'z' {
			letter := char + s - 'a'
			ind := (letter%26 + 26) % 26
			//-A fiindca alphabetul e din litere mari
			runesText[i] = alpha[ind] - 'A' + 'a'
		}
	}
	return string(runesText)
}

// acts like a constructor
func MakeCaesarCipher() CaesarCipher {
	return CaesarCipher{alphabet: []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ")}
}
