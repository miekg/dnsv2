// Package dns implements a fast and natural interface to the Domain Name Syste
package dns

type (
	Name  []byte
	Class [2]byte
	TTL   [4]byte
	// Eluding Type here, implicit from the RR type being used.

	Header struct {
		Name
		Class
		TTL
		// Implicit type
	}

	// An RR represents a resource record.
	RR interface {
		// Data returns the rdata at position i (zero based). If there is no data at that position nil is returned.
		Data(i int) []byte
		// Set sets rdata at position i with the data any.
		Set(i int, d any) error
		// String returns the string representation of the rdata.
		String() string
	}
)
