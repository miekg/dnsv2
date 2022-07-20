package dnswire

import (
	gob "encoding/binary"
)

// Error is returned when any parsing to wire format fails.
type Error string

func (e Error) Error() string {
	return "dns: " + string(e)
}

func TTL(v uint32, buf ...[4]byte) [4]byte { return Uint32(v, buf...) }

// Uint32 returns the wireformat of v.
func Uint32(v uint32, buf ...[4]byte) [4]byte {
	if buf != nil {
		gob.BigEndian.PutUint32((buf[0])[:], uint32(v))
	}
	return [4]byte{
		byte(v >> 24),
		byte(v >> 16),
		byte(v >> 8),
		byte(v),
	}
}

func MustName(s string, buf ...*[]byte) []byte {
	n, err := Name(s, buf...)
	if err != nil {
		panic("dns:" + err.Error())
	}
	return n
}

func Name(s string, buf ...*[]byte) ([]byte, error) {
	if s[len(s)-1] != '.' {
		return nil, Error("name must be fully qualified")
	}

	var n []byte
	if buf == nil {
		n = make([]byte, 0, 256)
	} else {
		n = *buf[0]
	}

	if s == "." {
		n = []byte{0}
		return n, nil
	}

	var (
		j       int
		escaped bool
	)

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
				return nil, Error("short label")
			}
			if ll > 63 {
				return nil, Error("label length exceeded")
			}
			n = append(n, []byte{byte(ll)}...)
			n = append(n, []byte(s[j:i])...)
			j = i + 1 // skip dot
		}

		escaped = false

	}
	n = append(n, byte(0))
	return n, nil
}
