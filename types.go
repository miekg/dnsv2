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
	Hdr Header
	A   [4]byte
}

func (rr *A) Data(i int) []byte {
	if i != 0 {
		return nil
	}
	return rr.A[:]
}

func (rr *A) SetData(i int, a net.IP) error {
	if i != 0 {
		return DataError("bad Data offset")
	}
	rr.A = *(*[4]byte)(a.To4())
	return nil
}

func (rr *A) String() string {
	return ""
}

/*
type CNAME struct {
	Hdr    Header
	Target Name
}
*/
