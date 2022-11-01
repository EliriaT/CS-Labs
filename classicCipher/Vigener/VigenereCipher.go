package Vigener

type VigenereCipher struct {
	key string
}

func (v *VigenereCipher) SetKey(key string) {
	v.key = key
}

func (v VigenereCipher) encodeChar(a, b rune) rune {
	return (((a - 'A') + (b - 'A')) % 26) + 'A'
}
func (v VigenereCipher) decodeChar(a, b rune) rune {
	return ((((a - 'A') - (b - 'A')) + 26) % 26) + 'A'
}

func (v VigenereCipher) Encrypt(text string) string {
	msg, key := cleanString(text), cleanString(v.key)
	out := make([]rune, 0, len(msg))
	for i, c := range msg {
		out = append(out, v.encodeChar(c, rune(key[i%len(key)])))
	}
	return string(out)
}

func (v VigenereCipher) Decrypt(text string) string {
	msg, key := cleanString(text), cleanString(v.key)
	out := make([]rune, 0, len(msg))
	for i, c := range msg {

		out = append(out, v.decodeChar(c, rune(key[i%len(key)])))
	}
	return string(out)
}

func (v VigenereCipher) Name() string {
	return "Vigenere Cipher"
}

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

// input parameter the key of the cipher
func MakeVigenereCipher(key string) VigenereCipher {
	return VigenereCipher{key: key}
}
