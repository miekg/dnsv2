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

	fmt.Println(rr.Data(0))
}
