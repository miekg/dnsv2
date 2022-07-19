// Package dns implements a fast and natural interface to the Domain Name Syste
package dns

import (
	gob "encoding/binary"
)

type (
	Name  []byte
	Class [2]byte
	TTL   [4]byte

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

func (t *TTL) Set(i int)     { gob.BigEndian.PutUint32((*t)[:], uint32(i)) }
func (c *Class) Set(d Class) { *c = d }

func (n *Name) Set(s string) error {
	// Any non escaped dot signals a label
	// First check for root domain.
	if s == "." {
		*n = []byte{0}
		return nil
	}
	if s[len(s)-1] != '.' {
		return ParseError("name must be fully qualified")
	}

	var (
		j       int
		escaped bool
	)

	if *n == nil {
		*n = make([]byte, 0, 256)
	}

	for i := 0; i < len(s); i++ {
		if !escaped && s[i] == '\\' {
			escaped = true
			continue
		}
		if escaped && s[i] == '.' {
			escaped = false
			continue
		}
		if !escaped && s[i] == '.' {
			ll := i - j
			if ll < 1 {
				return ParseError("short label")
			}
			if ll > 63 {
				return ParseError("label length exceeded")
			}
			*n = append(*n, []byte{byte(ll)}...)
			*n = append(*n, []byte(s[j:i])...)
			j = i + 1 // skip dot
		}

		escaped = false

	}
	*n = append(*n, byte(0))
	return nil
}
