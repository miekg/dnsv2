// Package dns implements a fast and natural interface to the Domain Name System.
package dns

import (
	"net"

	"github.com/miekg/dnsv2/dnswire"
)

type (
	Name  []byte  // Name is the owner name of the RR.
	Class [2]byte // Class the class of the RR.
	TTL   [4]byte // TTL is the TTL of the RR.
	Type  [2]byte // Type is the Type of an RR. An RR in this package is implicitaly typed via it's Go type.

	// Header is the header each RR has.
	Header struct {
		Name
		// Implicit type.
		Class
		TTL
	}

	RR interface {
		// Hdr returns a pointer to the header of the RR.
		Hdr() *Header
		// Len returns the number of rdata elements the RR has.
		Len() int
		// Data returns the rdata at position i (zero based). If there is no data at that position nil is returned.
		// The buffer returned is in wire format, i.e. if some data requires a length, that length is prepended to the buffer.
		Data(i int) []byte
		// String returns the string representation of the rdata(!) only.
		String() string
		// Write([]byte) (int, error)
		// Write the bytes into the rdata for each RR.
	}
)

// Copy of header and Copy of RR, make part of the RR interface?

// Mostly here, to prevent users from accessing the dnswire pkg directly. Not sure if this is a good idea.

// NewTTL returns a TTL from t. If buf is not nil the value is also written into it.
func NewTTL(t uint32, buf ...[]byte) TTL { return TTL(dnswire.Uint32(t, buf...)) }

// NewName returns a name from s. If buf is not nil the value is also written into it.
func NewName(s string, buf ...[]byte) Name { return Name(dnswire.String(s, buf...)) }

// NewIPv4 returns a 4 byte buffer from v. If buf is not nil the value is also written into it.
func NewIPv4(v net.IP, buf ...[]byte) [4]byte { return dnswire.IPv4(v, buf...) }
