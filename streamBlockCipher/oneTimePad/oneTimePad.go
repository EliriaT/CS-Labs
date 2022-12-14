package oneTimePad

import "fmt"

type Pad struct {
	pages       [][]byte
	currentPage int
}

// NewPad creates a new "one-time pad" by accepting arbitrary bytes from the
// hash and setting up pages from it. This method also allows passing the
// page pointer value to make resuming an existing pad easy.
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

// TotalPages returns the number of pages in the pad
func (p *Pad) TotalPages() int {
	return len(p.pages)
}

// RemainingPages returns the number of unused pages in the pad
func (p *Pad) RemainingPages() int {
	return len(p.pages) - p.currentPage
}

// CurrentPage returns the current position of the page pointer
func (p *Pad) CurrentPage() int {
	return p.currentPage
}

// getPage returns the payload of the current page
func (p *Pad) getPage() []byte {
	return p.pages[p.currentPage-1]
}

// SetPage will set the page pointer
func (p *Pad) SetPage(page int) error {
	if page < 1 || page > p.TotalPages() {
		return fmt.Errorf("otp: page %d out of bounds", page)
	}
	p.currentPage = page
	return nil
}

// NextPage will advance the page pointer
func (p *Pad) NextPage() error {
	if p.RemainingPages() == 0 {
		return fmt.Errorf("otp: pad exhausted")
	}
	p.currentPage++
	return nil
}

// Encrypt will take a byte slice and use modular addition to encrypt the
// payload byte by byte using the current page.
func (p *Pad) Encrypt(payload []byte) ([]byte, error) {
	page := p.getPage()

	// Page must be at least as long as plain text
	if len(page) < len(payload) {
		return nil, fmt.Errorf("otp: insufficient page size")
	}

	result := make([]byte, len(payload))

	for i := 0; i < len(payload); i++ {
		plainText := int(payload[i])
		secretKey := int(page[i])
		cipherText := (plainText + secretKey) % 255
		result[i] = byte(cipherText)
	}

	return result, nil
}

// Decrypt will accept a byte slice and will decrypt by reversing encrypted text back
// into raw bytes. It is required that the page
// pointer be set to the same position as it was during Encrypt().
func (p *Pad) Decrypt(payload []byte) ([]byte, error) {
	page := p.getPage()

	// Page must be at least as long as plain text
	if len(page) < len(payload) {
		return nil, fmt.Errorf("otp: insufficient page size")
	}

	result := make([]byte, len(payload))

	for i := 0; i < len(payload); i++ {
		cipherText := int(payload[i])
		secretKey := int(page[i])
		plainText := (cipherText - secretKey) % 255
		if plainText < 0 {
			plainText += 255
		}
		result[i] = byte(plainText)
	}

	return result, nil
}

func (p *Pad) Name() string {
	return "One Time Pad"
}
