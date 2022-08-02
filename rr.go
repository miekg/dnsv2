// Package dns implements a fast and natural interface to the Domain Name System.
package dns

import (
	"net"

	"github.com/miekg/dnsv2/dnswire"
)

type (
	Name  []byte  // Name is the owner name of the RR.
	Class [2]byte // Class is the class of the RR. Usually every RR has IN as its class.
	Type  [2]byte // Type is the Type of an RR. An RR in this package is implicitly typed via it's Go type.
	TTL   [4]byte // TTL is the time to live of the RR.

	// Header is the header each RR has.
	Header struct {
		Name
		// Implicit type.
		Class
		TTL
	}

	// RR defines a Resource Record. Note that even the special RR in the question section is handled as a normal
	// Resource Record (i.e with a zero TTL and no rdata).
	RR interface {
		// Hdr returns a pointer to the header of the RR.
		Hdr() *Header
		// Len returns the number of rdata elements the RR has. For RRs with a dynamic number of elements (i.e.
		// OPT, and others), this is not a constant number.
		Len() int
		// Data returns the rdata at position i (zero based). If there is no data at that position nil is
		// returned. The buffer returned is in wire format, i.e. if some data requires a length, that length is
		// prepended to the buffer.
		Data(i int) []byte
		// String returns the string representation of the rdata(!) only.
		String() string
		// Write writes the rdata encoded in msg starting at index offset and length n to the RR. Some rdata
		// needs access to the message's data, msg is expected to contain the targets of those pointers.
		Write(msg []byte, offset, n int) error
	}
)

// Mostly here, to prevent users from accessing the dnswire pkg directly. Not sure if this is a good idea.
// Do we need this for every Rdata type? NewIPv6, uint16s ? Etc etc??

// NewTTL returns a TTL from t. If buf is not nil the value is also written into it.
func NewTTL(t uint32, buf ...[]byte) TTL { return TTL(dnswire.Uint32(t, buf...)) }

// NewName returns a name from s. If buf is not nil the value is also written into it.
func NewName(s string, buf ...[]byte) Name { return Name(dnswire.String(s, buf...)) }

// NewIPv4 returns a 4 byte buffer from v. If buf is not nil the value is also written into it.
func NewIPv4(v net.IP, buf ...[]byte) [4]byte { return dnswire.IPv4(v, buf...) }
