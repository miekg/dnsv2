package dns

import (
	"fmt"
	"testing"

	dw "github.com/miekg/dnsv2/dnswire"
)

// Test function to test how the API feels.
func TestDNS(t *testing.T) {
	rr := &A{
		Hdr: Header{
			Name(dw.MustName("example.net.")),
			ClassINET,
			TTL(dw.TTL(15)),
		},
		A: dw.IPv4("127.0.0.1"),
	}

	fmt.Printf("%s %s\n", rr.Hdr.String(), rr.String())     // example.net. 15 IN A	224.0.0.2
	fmt.Printf("%#v %#v\n", rr.Hdr.GoString(), rr.String()) // "07example03net00 15 IN" "A\t224.0.0.2"
}
