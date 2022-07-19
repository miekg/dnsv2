package dns

import gob "encoding/binary"

func SetTTL(i int, ttl ...[4]byte) [4]byte {
	if ttl[0] != nil {
		gob.BigEndian.PutUint32(ttl[0][:], uint32(i))
		return
	}
	t := [4]byte{}
	gob.BigEndian.PutUint32(t[:], uint32(i))
	return t
}

func MustName(s string, buf ...[]byte) Name {
	n, err := NameFromString(s, buf)
	if err != nil {
		panic(err.Error())
	}
	return n
}

// shit name
func NameFromString(s string, buf ...[]byte) (Name, error) {
	// Any non escaped dot signals a label
	// First check for root domain.
	if s == "." {
		return Name([]byte{0}), nil
	}
	if s[len(s)-1] != '.' {
		return Name{}, ParseError("name must be fully qualified")
	}

	var (
		n       []byte
		j       int
		escaped bool
	)

	if buf != nil {
		n = buf
	} else {
		n = make([]byte, 0, 256)
	}

	for i := 0; i < len(s); i++ {
		if !escaped && s[i] == '\\' {
			escaped = true
			continue
		}
		if escaped && s[i] == '.' {
			escaped = false
			continue
		}
		if !escaped && s[i] == '.' {
			ll := i - j
			if ll < 1 {
				return Name{}, ParseError("short label")
			}
			if ll > 63 {
				return Name{}, ParseError("label length exceeded")
			}
			n = append(n, []byte{byte(ll)}...)
			n = append(n, []byte(s[j:i])...)
			j = i + 1 // skip dot
		}

		escaped = false

	}
	n = append(n, byte(0))
	return Name(n), nil
}
