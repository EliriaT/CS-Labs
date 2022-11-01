package Playfair

import (
	"fmt"
	"github.com/EliriaT/CS-Labs/classicCipher/implementations"
	"strings"
)

type PlayfairCipher struct {
	key   string
	table [5][5]string
}

func (p *PlayfairCipher) SetKey(key string) {
	p.ParseKey(key)
}

func (p *PlayfairCipher) ParseKey(key string) {
	key = implementations.cleanString(key)
	key = strings.Replace(key, "J", "I", -1)
	p.key = key

}

func (p *PlayfairCipher) makeCipherTable() {
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

func (p PlayfairCipher) Encrypt(text string) string {

	text = implementations.cleanString(text)
	length := len(text)/2 + len(text)%2

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

	var encrypted string

	encDigraphs := make([]string, length, length)
	encDigraphs = p.encodeDigraph(digraph, length)

	for k := 0; k < length; k++ {

		encrypted = encrypted + encDigraphs[k]
	}
	return encrypted
}

func (p *PlayfairCipher) encodeDigraph(di []string, length int) []string {
	encipher := make([]string, length, length)

	for i := 0; i < length; i++ {
		a := di[i][0]
		b := di[i][1]
		r1 := p.getPoint(rune(a)).x
		r2 := p.getPoint(rune(b)).x
		c1 := p.getPoint(rune(a)).y
		c2 := p.getPoint(rune(b)).y

		if r1 == r2 {
			c1 = (c1 + 1) % 5
			c2 = (c2 + 1) % 5
		} else if c1 == c2 {
			r1 = (r1 + 1) % 5
			r2 = (r2 + 1) % 5
		} else {
			temp := c1
			c1 = c2
			c2 = temp
		}

		//performs the table look-up and puts those values into the encoded array
		encipher[i] = p.table[r1][c1] + "" + p.table[r2][c2]
	}
	return encipher
}

func (p *PlayfairCipher) getPoint(c rune) *Point {
	pt := new(Point)
	for i := 0; i < 5; i++ {
		for j := 0; j < 5; j++ {
			if string(c) == string(p.table[i][j][0]) {
				pt.x = i
				pt.y = j

			}
		}
	}
	return pt
}

func (p PlayfairCipher) Decrypt(text string) string {
	var decoded string

	for i := 0; i < len(text)/2; i++ {
		a := text[2*i]
		b := text[2*i+1]
		r1 := p.getPoint(rune(a)).x
		r2 := p.getPoint(rune(b)).x
		c1 := p.getPoint(rune(a)).y
		c2 := p.getPoint(rune(b)).y

		if r1 == r2 {
			c1 = (c1 + 4) % 5
			c2 = (c2 + 4) % 5
		} else if c1 == c2 {
			r1 = (r1 + 4) % 5
			r2 = (r2 + 4) % 5
		} else {

			temp := c1
			c1 = c2
			c2 = temp
		}
		decoded = decoded + p.table[r1][c1] + p.table[r2][c2]
	}

	return decoded
}

func (p PlayfairCipher) Name() string {
	return "Playfair cipher"
}

func (p PlayfairCipher) keyTable() {
	fmt.Println("Playfair Cipher Key Matrix: \n")

	//loop iterates for rows
	for i := 0; i < 5; i++ {
		//loop iterates for column
		for j := 0; j < 5; j++ {
			//prints the key-table in matrix form
			fmt.Print(p.table[i][j] + " ")
		}
		fmt.Println()
	}

}

// input parameter the key of the cipher
func MakePlayfairCipher(key string) PlayfairCipher {
	c := PlayfairCipher{}
	c.SetKey(key)
	c.makeCipherTable()
	return c
}

type Point struct {
	x int
	y int
}
