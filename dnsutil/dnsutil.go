package dnsutil

import (
	"strings"

	"github.com/miekg/dnsv2/internal/ddd"
)

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

// IsName checks if s is a valid domain name.  Note that non fully qualified
// domain name is considered valid, in this case the last label is counted in
// the number of labels.  When false is returned the number of labels is not
// defined.  Also note that this function is extremely liberal; almost any
// string is a valid domain name as the DNS is 8 bit protocol. It checks if each
// label fits in 63 characters and that the entire name will fit into the 255
// octet wire format limit.
func IsName(s string) (labels int, ok bool) {
	// XXX: The logic in this function was copied from packDomainName and
	// should be kept in sync with that function.

	const lenmsg = 256

	s = Fqdn(s)

	// Each dot ends a segment of the name. Except for escaped dots (\.), which
	// are normal dots.

	var (
		off    int
		begin  int
		wasDot bool
	)
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			if off+1 > lenmsg {
				return labels, false
			}

			// check for \DDD
			if ddd.Is(s[i+1:]) {
				i += 3
				begin += 3
			} else {
				i++
				begin++
			}

			wasDot = false
		case '.':
			if i == 0 && len(s) > 1 {
				// leading dots are not legal except for the root zone
				return labels, false
			}

			if wasDot {
				// two dots back to back is not legal
				return labels, false
			}
			wasDot = true

			labelLen := i - begin
			if labelLen >= 1<<6 { // top two bits of length must be clear
				return labels, false
			}

			// off can already (we're in a loop) be bigger than lenmsg
			// this happens when a name isn't fully qualified
			off += 1 + labelLen
			if off > lenmsg {
				return labels, false
			}

			labels++
			begin = i + 1
		default:
			wasDot = false
		}
	}

	return labels, true
}

// Trim removes the zone component from q. It returns the trimmed
// name or an error is zone is longer then qname. The trimmed name will be returned
// without a trailing dot.
func Trim(q string, z string) string {
	zl := Count(z)
	i, ok := Prev(q, zl)
	if ok || i-1 < 0 {
		return ""
	}
	// This includes the '.', remove on return
	return q[:i-1]
}
