package dnsutil

import (
	"net"
	"strconv"
	"strings"

	dns "github.com/miekg/dnsv2"
)

// IsFqdn checks if a domain name is fully qualified.
func IsFqdn(s string) bool {
	// Check for (and remove) a trailing dot, returning if there isn't one.
	if s == "" || s[len(s)-1] != '.' {
		return false
	}
	s = s[:len(s)-1]

	// If we don't have an escape sequence before the final dot, we know it's
	// fully qualified and can return here.
	if s == "" || s[len(s)-1] != '\\' {
		return true
	}

	// Otherwise we have to check if the dot is escaped or not by checking if
	// there are an odd or even number of escape sequences before the dot.
	i := strings.LastIndexFunc(s, func(r rune) bool {
		return r != '\\'
	})
	return (len(s)-i)%2 != 0
}

// IsRRset reports whether a set of RRs is a valid RRset as defined by RFC 2181.
// This means the RRs need to have the same type, name, and class.
func IsRRset(rrset []dns.RR) bool {
	if len(rrset) == 0 {
		return false
	}

	baseH := rrset[0].Header()
	for _, rr := range rrset[1:] {
		curH := rr.Header()
		if curH.Rrtype != baseH.Rrtype || curH.Class != baseH.Class || curH.Name != baseH.Name {
			// Mismatch between the records, so this is not a valid rrset for
			// signing/verifying
			return false
		}
	}

	return true
}

// Fqdn return the fully qualified domain name from s.
// If s is already fully qualified, it behaves as the identity function.
func Fqdn(s string) string {
	if IsFqdn(s) {
		return s
	}
	return s + "."
}

// CanonicalName returns the domain name in canonical form. A name in canonical
// form is lowercase and fully qualified. Only US-ASCII letters are affected. See
// Section 6.2 in RFC 4034.
func CanonicalName(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			r += 'a' - 'A'
		}
		return r
	}, Fqdn(s))
}

// Copied from the official Go code.

// ReverseAddr returns the in-addr.arpa. or ip6.arpa. hostname of the IP
// address suitable for reverse DNS (PTR) record lookups or an error if it fails
// to parse the IP address.
func ReverseAddr(addr string) (arpa string, err error) {
	ip := net.ParseIP(addr)
	if ip == nil {
		return "", &Error{err: "unrecognized address: " + addr}
	}
	if v4 := ip.To4(); v4 != nil {
		buf := make([]byte, 0, net.IPv4len*4+len("in-addr.arpa."))
		// Add it, in reverse, to the buffer
		for i := len(v4) - 1; i >= 0; i-- {
			buf = strconv.AppendInt(buf, int64(v4[i]), 10)
			buf = append(buf, '.')
		}
		// Append "in-addr.arpa." and return (buf already has the final .)
		buf = append(buf, "in-addr.arpa."...)
		return string(buf), nil
	}
	// Must be IPv6
	buf := make([]byte, 0, net.IPv6len*4+len("ip6.arpa."))
	// Add it, in reverse, to the buffer
	for i := len(ip) - 1; i >= 0; i-- {
		v := ip[i]
		buf = append(buf, hexDigit[v&0xF], '.', hexDigit[v>>4], '.')
	}
	// Append "ip6.arpa." and return (buf already has the final .)
	buf = append(buf, "ip6.arpa."...)
	return string(buf), nil
}
