package dns

import (
	"fmt"
	"net"
	"testing"
)

// Test function to test how the API feels.
func TestDNS(t *testing.T) {
	rr := new(A)
	rr.Hdr.Name.Set("example.net.")
	rr.Hdr.Class.Set(ClassINET)
	rr.Hdr.TTL.Set(15)
	rr.SetData(0, net.IPv4allrouter)

	fmt.Printf("%s %s\n", rr.Hdr.String(), rr.String())     // example.net. 15 IN A	224.0.0.2
	fmt.Printf("%#v %#v\n", rr.Hdr.GoString(), rr.String()) // "07example03net00 15 IN" "A\t224.0.0.2"
}
