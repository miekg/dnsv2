package dns

import (
	gob "encoding/binary"
	"net"
)

var (
	// Valid Classes.
	ClassNONE = [2]byte{0, 254}
	ClassINET = [2]byte{0, 1}
	classANY  = [2]byte{0, 255}
)

// A RR. See RFC 1035.
type A struct {
	Header
	A [4]byte
}

func (rr *A) Hdr() Header { return rr.Header }
func (rr *A) Len() int    { return 1 }
func (rr *A) String() string {
	return "A\t" + net.IP{rr.A[0], rr.A[1], rr.A[2], rr.A[3]}.String()
}

func (rr *A) Data(i int) []byte {
	if i != 0 {
		return nil
	}
	return rr.A[:]
}

/*
type CNAME struct {
	Hdr    Header
	Target Name
}
*/

// Supported RR Types.
var (
	TypeNone = [2]byte{0, 0}
	TypeA    = [2]byte{0, 1}
)

// Type returns the type of the RR.
func Type(rr RR) [2]byte {
	switch rr.(type) {
	case *A:
		return TypeA
	}
	return TypeNone
}

/*
WireBytes converts an RR to the format we can use on the wire. The format is described
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
func WireBytes(rr RR) []byte {
	// this now allocates a buffer, actual function will let you choose. And compression and stuff.
	buf := make([]byte, 256)
	n := copy(buf[0:], rr.Hdr().Name)

	buf[n+1] = Type(rr)[0]
	buf[n+2] = Type(rr)[1]
	n += 2

	buf[n+1] = rr.Hdr().Class[0]
	buf[n+2] = rr.Hdr().Class[1]
	n += 2

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
	gob.BigEndian.PutUint16(buf[rdlen+1:], uint16(l))
	return buf[:j+1]
}
