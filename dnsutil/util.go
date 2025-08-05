// Package dnsutil contains DNS related helper functions that are somewhat non-trivial, but very handy when
// writing DNS servers and clients.
package dnsutil

import (
	"bytes"

	"github.com/miekg/dns"
	"github.com/miekg/dnsv2/dnswire"
)

// Join joins names to form a new fully qualified domain name. If the last name is the root name it is ignored.
func Join(names ...dnswire.Name) dnswire.Name {
	// todo
	return nil
}

// FromReverse turns a standard PTR reverse record name into an IP address that can be parsed with
// [net.ParseIP]. This works for IPv4 or IPv6.
//
// 54.119.58.176.in-addr.arpa. return 176.58.119.54. If the conversion fails the empty string is returned.
func FromReverse(reverse dnswire.Name) string {
	return ""
}

// or

// Reverse returns the standard reverse record name of a PTR record into an IP address.
func Reverse(ptr dns.PTR) string {
	return ""
	// or dnswire.Name?
}

// IsReverse returns 0 if name is not in a reverse zone. The returned integer will be 1 for in-addr.arpa. (IPv4)
// and 2 for ip6.arpa. (IPv6).
func IsReverse(name dnswire.Name) int {
	if bytes.HasSuffix(name, IP4arpa) {
		return 1
	}
	if bytes.HasSuffix(name, IP6arpa) {
		return 2
	}
	return 0
}

var (
	// IP4arpa is the reverse tree suffix for v4 IP addresses.
	IP4arpa = dnswire.Name{}.Marshal(".in-addr.arpa.")
	// IP6arpa is the reverse tree suffix for v6 IP addresses.
	IP6arpa = dnswire.Name{}.Marshal(".ip6.arpa.")
)

// TrimOrigin removes the origin component from name. It returns the trimmed name or the original name if it doesn't have
// origin as a suffix. TDDO: what about the closing 00 byte?
func TrimOrigin(name, origin dnswire.Name) dnswire.Name {
	return bytes.TrimSuffix(name, origin)
}
