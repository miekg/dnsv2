// Package dns implements a fast and natural interface to the Domain Name Syste
package dns

import (
	"strconv"
	"strings"
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
		// SetData sets rdata at position i with the data any.
		SetData(i int, d any) ([]byte, error)
		// String returns the string representation.
		String() string
	}
)

// +#v
func (n Name) GoString() string {
	if len(n) == 0 {
		return ""
	}
	if n[0] == 0 {
		return "00"
	}
	b := &strings.Builder{}
	for i := 0; i < len(n); {
		v := int(n[i])
		ll := strconv.Itoa(v)
		if v < 10 {
			b.WriteString("0")
		}
		b.WriteString(ll)
		// i+1 ... i+ll is the labels "text"
		b.Write(n[i+1 : i+1+v])
		i += v + 1
	}

	return b.String()
}

func (n Name) String() string {
	if len(n) == 0 {
		return ""
	}
	if n[0] == 0 {
		return "."
	}
	b := &strings.Builder{}
	for i := 0; i < len(n); {
		v := int(n[i])
		if i > 0 { // don't want to start with a dot
			b.WriteString(".")
		}
		// i+1 ... i+ll is the labels "text"
		b.Write(n[i+1 : i+1+v])
		i += v + 1
	}

	return b.String()
}
