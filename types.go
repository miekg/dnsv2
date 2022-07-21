package dns

import "net"

var (
	TypeNone = [2]byte{0, 0}
	TypeA    = [2]byte{0, 1}
)

var (
	ClassINET = [2]byte{0, 1}
)

// A RR. See RFC 1035.
type A struct {
	Header
	A [4]byte
}

func (rr *A) Hdr() Header { return rr.Header }
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
