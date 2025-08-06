package dnsutil

import "strings"

// Fqdn return the fully qualified domain name from s. If s is already fully qualified, it behaves as the identity function.
func Fqdn(s string) string {
	if IsFqdn(s) {
		return s
	}
	return s + "."
}

// IsFqdn checks if a domain name is fully qualified. Note that due the escapes in the names this is not
// completely trivial to establish.
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

// Canonical returns the domain name in canonical form. A name in canonical form is lowercase and fully qualified.
// / Only US-ASCII letters are affected. See Section 6.2 in RFC 4034.
func Canonical(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			r += 'a' - 'A'
		}
		return r
	}, Fqdn(s))
}
