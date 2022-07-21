package dnswire

import (
	gob "encoding/binary"
	"net"
)

// Uint32 returns the wire format of v.
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

// String returns the wire format of the string v. On error nil is returned.
func String(v string, buf ...[]byte) []byte {
	if v[len(v)-1] != '.' {
		return nil
	}

	var n []byte
	if buf == nil {
		n = make([]byte, 0, 256)
	} else {
		n = buf[0]
	}

	if v == "." {
		n = []byte{0}
		return n
	}

	var (
		j       int
		escaped bool
	)

	for i := 0; i < len(v); i++ {
		if !escaped && v[i] == '\\' {
			escaped = true
			continue
		}
		if escaped && v[i] == '.' {
			escaped = false
			continue
		}
		if !escaped && v[i] == '.' {
			ll := i - j
			if ll < 1 {
				return nil
			}
			if ll > 63 {
				return nil
			}
			n = append(n, []byte{byte(ll)}...)
			n = append(n, []byte(v[j:i])...)
			j = i + 1 // skip dot
		}

		escaped = false

	}
	n = append(n, byte(0))
	return n
}

// IPv4 returns the wire format of the IP v.
func IPv4(v net.IP, buf ...[4]byte) [4]byte {
	if buf == nil {
		return *(*[4]byte)(v.To4())

	}
	ip := v.To4()
	buf[0][0] = ip[0]
	buf[0][1] = ip[1]
	buf[0][2] = ip[2]
	buf[0][3] = ip[3]
	return buf[0]
}
