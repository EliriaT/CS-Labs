package implementations

type CaesarCipher struct {
	key      int
	alphabet string
}

func (c *CaesarCipher) SetKey(a int) {
	c.key = a
}
func (c *CaesarCipher) Encrypt(text string) string {
	return c.convertText(text, c.key)
}
func (c *CaesarCipher) Decrypt(text string) string {
	return c.convertText(text, -c.key)
}

func (c *CaesarCipher) convertText(text string, key int) string {
	alpha := []rune(c.alphabet)
	s := rune(key)
	runes := []rune(text)
	for i, char := range runes {
		if char >= 'A' && char <= 'Z' {
			letter := char + s - 'A'
			ind := (letter%26 + 26) % 26
			runes[i] = alpha[ind]
		} else if char >= 'a' && char <= 'z' {
			letter := char + s - 'a'
			ind := (letter%26 + 26) % 26
			//-A fiindca alphabetul e din litere mari
			runes[i] = alpha[ind] - 'A' + 'a'
		}
	}
	return string(runes)
}

// acts like a constructor
func MakeCaesarCipher() CaesarCipher {
	return CaesarCipher{alphabet: "ABCDEFGHIJKLMNOPQRSTUVWXYZ"}
}
