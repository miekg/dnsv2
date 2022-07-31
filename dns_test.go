package dns

import (
	"fmt"
	"net"
	"strings"
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

func TestMsgQuery(t *testing.T) {
	m := &Msg{Buf: query}
	println(m.Count(Qd))
	println(m.Count(An))
	println(m.Count(Ns))
	println(m.Count(Ar))
	println("L", len(m.Buf))
	rr, err := m.RR(Ar)
	if err != nil {
		println(err.Error())
	}
	println(m.r[Qd], m.r[An], m.r[Ns], m.r[Ar])
	println("parsed", rr.Hdr().String(), rr.String())
	rr, err = m.RR(Qd)
	if err != nil {
		println(err.Error())
	}
	println("parsed", rr.Hdr().String(), rr.String())
}

func TestMsgReply(t *testing.T) {
	m := &Msg{Buf: reply}

	answer, err := m.RRs(An)
	if err != nil {
		t.Errorf(err.Error())
	}
	for _, rr := range answer {
		fmt.Printf("%s %s\n", rr.Hdr(), rr)
	}

	opt, err := m.RR(Ar)
	if err != nil {
		t.Errorf(err.Error())
	}
	fmt.Printf("%s %s\n", opt.Hdr(), opt)
}

func TestMsgString(t *testing.T) {
	m := &Msg{Buf: reply}
	b := &strings.Builder{}
	b.WriteString(m.String())
	for s := Qd; s <= Ar; s++ {
		if m.Count(s) == 0 {
			continue
		}
		b.WriteString(fmt.Sprintf(";; %s SECTION:\n", s))
		rrs, err := m.RRs(s)
		if err != nil {
			t.Errorf(err.Error())
		}
		for _, rr := range rrs {
			if _, ok := rr.(*OPT); ok {
				// treat differenty
			}
			if s == Qd {
				b.WriteString(rr.Hdr().Name.String())
				b.WriteString(" ")
				b.WriteString(rr.Hdr().Class.String())
				b.WriteString(" ")
				b.WriteString(RRType(rr).String())
				b.WriteString("\n")
				continue
			}
			b.WriteString(rr.Hdr().String())
			b.WriteString("\t")
			b.WriteString(rr.String())
			b.WriteString("\n")
		}
	}
	println(b.String())
}

func TestMsgStringQuery(t *testing.T) {

}

func TestSkip(t *testing.T) {
	m := &Msg{Buf: reply}
	i := m.skipName(12)
	if i != 20 {
		t.Errorf("expected offset after qname %d, got %d", 20, i)
	}
	// First RR starts at 25 here.
	i = m.skipRR(25)
	if i != 63 {
		t.Errorf("expected offset after 1st skipRR %d, got %d", 63, i)
	}
	i = m.skipRR(i + 1)
	if i != 79 {
		t.Errorf("expected offset after 2nd skipRR %d, got %d", 79, i)
	}
	i = m.skipRR(i + 1)
	if i != 113 {
		t.Errorf("expected offset after 3rd skipRR %d, got %d", 113, i)
	}
	i = m.skipRR(i + 1)
	if i != 136 {
		t.Errorf("expected offset after 4th skipRR %d, got %d", 136, i)
	}
	i = m.skipRR(i + 1)
	if i != 157 {
		t.Errorf("expected offset after 5th skipRR %d, got %d", 157, i)
	}
	// OPT RR
	i = m.skipRR(i + 1)
	if i != 168 {
		t.Errorf("expected offset after OPT RR %d, got %d", 168, i)
	}
	i = m.skipRR(i + 1)
	if i != 0 {
		t.Errorf("expected offset after msg length %d, got %d", 0, i)
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
