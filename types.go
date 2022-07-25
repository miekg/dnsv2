package dns

import (
	"fmt"
	"net"

	"github.com/miekg/dnsv2/dnswire"
)

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

/*
OPT is the EDNS0 RR appended to messages to convey extra (meta) information. See RFC 6891.
Each option is encoded as:

               +0 (MSB)                            +1 (LSB)
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
   0: |                          OPTION-CODE                          |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
   2: |                         OPTION-LENGTH                         |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
   4: |                                                               |
      /                          OPTION-DATA                          /
      /                                                               /
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
*/
type OPT struct {
	Header
	Options []Option
}

func (rr *OPT) Hdr() *Header   { return &rr.Header }
func (rr *OPT) Len() int       { return len(rr.Options) }
func (rr *OPT) String() string { return "TODO" }
func (rr *OPT) Data(i int) []byte {
	if i < 0 || i >= rr.Len() {
		return nil
	}
	return rr.Options[i].Data()
}

// A RR. See RFC 1035.
type A struct {
	Header
	A [4]byte
}

func (rr *A) Hdr() *Header { return &rr.Header }
func (rr *A) Len() int     { return 1 }
func (rr *A) String() string {
	return "A\t" + net.IP{rr.A[0], rr.A[1], rr.A[2], rr.A[3]}.String()
}

func (rr *A) Data(i int) []byte {
	if i != 0 {
		return nil
	}
	return rr.A[:]
}

// MX RR. See RFC 1035.
type MX struct {
	Header
	Preference [2]byte
	Mx         Name
}

func (rr *MX) Hdr() *Header { return &rr.Header }
func (rr *MX) Len() int     { return 2 }
func (rr *MX) String() string {
	return "MX\t" + rr.Mx.String()
}

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

The bytes are copied into a newly allocated memory buffer.
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

// Write writes buffer buf into the RRs rdata.
func Write(rr RR, buf []byte) error {
	switch x := rr.(type) {
	case *A:
		if len(buf) != 4 {
			return fmt.Errorf("nono")
		}
		x.A[0] = buf[0]
		x.A[1] = buf[1]
		x.A[2] = buf[2]
		x.A[3] = buf[3]
		return nil

	}
	return nil
}

var typeToRR = map[Type]func() RR{
	TypeA:   func() RR { return new(A) },
	TypeMX:  func() RR { return new(MX) },
	TypeOPT: func() RR { return new(OPT) },
}
