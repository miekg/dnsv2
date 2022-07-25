package dns

import (
	"fmt"
	"net"
	"testing"
)

// miek.nl. IN MX request and reply. Both contains OPT RR as well.
// both are compressed.
var (
	query = []byte{
		0xe9, 0x71, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01, 0x04, 0x6d, 0x69, 0x65,
		0x6b, 0x02, 0x6e, 0x6c, 0x00, 0x00, 0x0f, 0x00,
		0x01, 0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x0c, 0x00, 0x0a, 0x00, 0x08,
		0x71, 0xa1, 0xd7, 0x18, 0x60, 0xe4, 0x4d, 0x06,
	}
	reply = []byte{
		0xe9, 0x71, 0x81, 0xa0, 0x00, 0x01, 0x00, 0x05,
		0x00, 0x00, 0x00, 0x01, 0x04, 0x6d, 0x69, 0x65,
		0x6b, 0x02, 0x6e, 0x6c, 0x00, 0x00, 0x0f, 0x00,
		0x01, 0xc0, 0x0c, 0x00, 0x0f, 0x00, 0x01, 0x00,
		0x00, 0x03, 0x84, 0x00, 0x1b, 0x00, 0x05, 0x04,
		0x61, 0x6c, 0x74, 0x32, 0x05, 0x61, 0x73, 0x70,
		0x6d, 0x78, 0x01, 0x6c, 0x06, 0x67, 0x6f, 0x6f,
		0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
		0xc0, 0x0c, 0x00, 0x0f, 0x00, 0x01, 0x00, 0x00,
		0x03, 0x84, 0x00, 0x04, 0x00, 0x01, 0xc0, 0x2c,
		0xc0, 0x0c, 0x00, 0x0f, 0x00, 0x01, 0x00, 0x00,
		0x03, 0x84, 0x00, 0x16, 0x00, 0x0a, 0x06, 0x61,
		0x73, 0x70, 0x6d, 0x78, 0x32, 0x0a, 0x67, 0x6f,
		0x6f, 0x67, 0x6c, 0x65, 0x6d, 0x61, 0x69, 0x6c,
		0xc0, 0x3b, 0xc0, 0x0c, 0x00, 0x0f, 0x00, 0x01,
		0x00, 0x00, 0x03, 0x84, 0x00, 0x0b, 0x00, 0x0a,
		0x06, 0x61, 0x73, 0x70, 0x6d, 0x78, 0x33, 0xc0,
		0x65, 0xc0, 0x0c, 0x00, 0x0f, 0x00, 0x01, 0x00,
		0x00, 0x03, 0x84, 0x00, 0x09, 0x00, 0x05, 0x04,
		0x61, 0x6c, 0x74, 0x31, 0xc0, 0x2c, 0x00, 0x00,
		0x29, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00,
	}
)

func TestMsg(t *testing.T) {
	m := &Msg{Buf: query}
	println(m.Count(Qd))
	println(m.Count(An))
	println(m.Count(Ns))
	println(m.Count(Ar))
	println("L", len(m.Buf))
	m.index()
	println(m.r[0], m.r[1], m.r[2])
	m = &Msg{Buf: reply}
	println("L", len(m.Buf))
	m.index()
	println(m.r[0], m.r[1], m.r[2])
	rr, err := m.RR(An)
	if err != nil {
		println(rr.String())
	}
}

// Test function to test how the API feels.
func TestDNS(t *testing.T) {
	rr := &A{
		Header{NewName("example.net."), ClassINET, NewTTL(15)},
		NewIPv4(net.ParseIP("127.0.0.1")),
	}

	fmt.Printf("%s %s\n", rr.Hdr().String(), rr.String()) // example.net. 15 IN A	224.0.0.2
	fmt.Printf("%#v\n", rr.Hdr().Name)                    // 06example03net00

	fmt.Printf("This RR has %d rdatas\n", rr.Len())
	fmt.Printf("This is the first: %v\n", rr.Data(0))

	wirebuf := Bytes(rr)
	fmt.Printf("This is its complete wireformat: %+v\n", wirebuf)
}

func TestEDNS0(t *testing.T) {
	opt := &OPT{Header: Header{Name: NewName(".")}}
	nsid := &NSID{ID: []byte("AA")}
	opt.Options = []Option{nsid}

	wirebuf := Bytes(opt)
	fmt.Printf("This is its complete wireformat: %+v\n", wirebuf)
}
