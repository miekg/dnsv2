package dns

import (
	"fmt"
	"net"

	"github.com/miekg/dnsv2/dnswire"
)

// worth doing this and not just uint16?

var (
	// Valid Classes.
	ClassNONE = Class{0, 254}
	ClassINET = Class{0, 1}
	classANY  = Class{0, 255}

	// Supported RR Types.
	TypeNone = Type{0, 0}
	TypeA    = Type{0, 1}
	TypeMX   = Type{0, 15}
	TypeOPT  = Type{0, 41}
)

// A RR. See RFC 1035.
type A struct {
	Header
	A [4]byte
}

func (rr *A) Hdr() *Header { return &rr.Header }
func (rr *A) Len() int     { return 1 }
func (rr *A) String() string {
	return TypeToString[TypeA] + "\t" + net.IP{rr.A[0], rr.A[1], rr.A[2], rr.A[3]}.String()
}

func (rr *A) Data(i int) []byte {
	if i != 0 {
		return nil
	}
	return rr.A[:]
}

func (rr *A) Write(buf []byte, msg ...[]byte) error {
	if len(buf) != 4 {
		return fmt.Errorf("A rdata must be 4 bytes")
	}
	rr.A[0] = buf[0]
	rr.A[1] = buf[1]
	rr.A[2] = buf[2]
	rr.A[3] = buf[3]
	return nil
}

// MX RR. See RFC 1035.
type MX struct {
	Header
	Preference [2]byte
	Mx         Name
}

func (rr *MX) Hdr() *Header   { return &rr.Header }
func (rr *MX) Len() int       { return 2 }
func (rr *MX) String() string { return TypeToString[TypeMX] + "\t" + rr.Mx.String() }

func (rr *MX) Data(i int) []byte {
	if i < 0 || i > 2 {
		return nil
	}
	switch i {
	case 0:
		return rr.Preference[:]
	case 1:
		return rr.Name
	}
	return nil
}

func (rr *MX) Write(buf []byte, msg ...[]byte) error {
	// getname
	return nil
}

var (
	_ RR = new(A)
	_ RR = new(MX)
	_ RR = new(OPT)
)

/*
type CNAME struct {
	Hdr    Header
	Target Name
}
*/

// RRType returns the type of the RR.
func RRType(rr RR) [2]byte {
	switch rr.(type) {
	case *A:
		return TypeA
	case *MX:
		return TypeMX
	case *OPT:
		return TypeOPT
	}
	return TypeNone
}

/*
Bytes converts an RR to the format we can use on the wire. The format is described
in RFC 1035:

                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                                               /
    /                      NAME                     /
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     CLASS                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TTL                      |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                   RDLENGTH                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    /                     RDATA                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

The bytes are copied into a newly allocated memory buffer. TODO
*/
func Bytes(rr RR) []byte {
	// this now allocates a buffer, actual function will let you choose. And compression and stuff.
	buf := make([]byte, 256)
	n := copy(buf[0:], rr.Hdr().Name)
	buf[n+0] = RRType(rr)[0]
	buf[n+1] = RRType(rr)[1]
	buf[n+2] = rr.Hdr().Class[0]
	buf[n+3] = rr.Hdr().Class[1]
	n += 3

	buf[n+1] = rr.Hdr().TTL[0]
	buf[n+2] = rr.Hdr().TTL[1]
	buf[n+3] = rr.Hdr().TTL[2]
	buf[n+4] = rr.Hdr().TTL[3]
	n += 4

	rdlen := n // length start
	n += 2

	l := 0
	j := n
	for i := 0; i < rr.Len(); i++ {
		// for compression I need to knows which rdata of which RR is compressible, finite set, so can be done here
		n = copy(buf[j+1:], rr.Data(i))
		j += n
		l += n
	}
	dnswire.Uint16(uint16(l), buf[rdlen+1:])
	return buf[:j+1]
}

var typeToRR = map[Type]func() RR{
	TypeA:   func() RR { return new(A) },
	TypeMX:  func() RR { return new(MX) },
	TypeOPT: func() RR { return new(OPT) },
}

var TypeToString = map[Type]string{
	TypeA:   "A",
	TypeMX:  "MX",
	TypeOPT: "OPT",
}
