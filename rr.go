// Package dns implements a fast and natural interface to the Domain Name Syste
package dns

import (
	"net"

	"github.com/miekg/dnsv2/dnswire"
)

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
		// Hdr returns the header of the RR.
		Hdr() Header
		// Data returns the rdata at position i (zero based). If there is no data at that position nil is returned.
		Data(i int) []byte
		// String returns the string representation of the rdata(!) only.
		String() string
	}
)

func NewTTL(t uint32, buf ...[4]byte) TTL      { return TTL(dnswire.Uint32(t, buf...)) }
func NewName(s string, buf ...[]byte) Name     { return Name(dnswire.String(s, buf...)) }
func NewIPv4(v net.IP, buf ...[4]byte) [4]byte { return dnswire.IPv4(v, buf...) }
