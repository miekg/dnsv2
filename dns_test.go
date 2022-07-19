package dns

import "testing"

// Test function to test how the API feels.
func TestDNS(t *testing.T) {
	rr := &A{
		Hdr: Header{
			Name:  MustName("example.net."),
			Class: ClassINET,
			TTL:   SetTTL(15),
		},
	}

}
