package dns

import "net"

// RFC3597 represents an unknown/generic RR. See RFC 3597.
type RFC3597 struct {
	Header
	octets []byte `dns:"Data:Hex"`
}

// A RR. See RFC 1035.
type A struct {
	Header
	A net.IP `dns:"a"`
}

// PTR RR. See RFC 1035.
type PTR struct {
	Header
	Ptr string `dns:"cdomain-name"`
}

// AAAA RR. See RFC 3596.
type AAAA struct {
	Header
	AAAA net.IP `dns:"aaaa"`
}

// MX RR, See RFC 1035.
type MX struct {
	Header
	Preference uint16
	Mx         string `dns:"cdomain-name"`
}

// NS RR. See RFC 1035.
type NS struct {
	Header
	Ns string `dns:"cdomain-name"`
}

// SOA RR. See RFC 1035.
type SOA struct {
	Header
	Ns      string `dns:"cdomain-name"`
	Mbox    string `dns:"cdomain-name"`
	Serial  uint32
	Refresh uint32
	Retry   uint32
	Expire  uint32
	Minttl  uint32
}

// OPT is the EDNS0 RR appended to messages to convey extra (meta) information. See RFC 6891.
type OPT struct {
	Header
	Option []EDNS0
}
