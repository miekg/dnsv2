package dns

import (
	"fmt"
	"net"
	"testing"
)

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

func TestQuestion(t *testing.T) {
	q := &Question{NewName("example.net."), TypeA, ClassINET}
	fmt.Printf("Question %s %s\n", q.Hdr(), q)

}

func TestMsg(t *testing.T) {
	m := NewMsg(make([]byte, 256))
	m.SetRR(Qd, &Question{NewName("example.net."), TypeA, ClassINET})
	rr := &A{
		Header{NewName("example.net."), ClassINET, NewTTL(15)},
		NewIPv4(net.ParseIP("127.0.0.1")),
	}
	m.SetRR(An, rr)
	fmt.Printf("Msg %s %v\n", m.Bytes(), m.Bytes())
}
