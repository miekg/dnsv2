package dns

import (
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

	println(rr.String())
}
