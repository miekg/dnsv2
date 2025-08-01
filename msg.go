package dns

import (
	"encoding/binary"
)

func (m *Msg) Octets(x ...[]byte) []byte {
	if len(x) == 0 {
		return m.octets
	}
	m.octets = x[0]
	return nil
}

func (m *Msg) Question() (Section, error) {
	// The question sections starts a offset 12. There is not a complete RR here, but only name, qtype and
	// class. The RFC says it should only be 1 of those, but multiple may be present, we don't care.
	start := 12
	if len(m.octets) < 12 {
		return Section{}, ErrBuf
	}
	// find the end using the question count.
	end := jumpsection(m.octets, start, int(m.Qdcount()))
	return Section{msg: m, octets: m.octets[start:end]}, nil
}

func (m *Msg) Answer() Section {
	return Section{}
}

func (m *Msg) Ns() Section {
	return Section{}
}

func (m *Msg) Extra() Section {
	return Section{}
}

func (m *Msg) Pseudo() Section {
	return Section{}
}

// Qdcount returns the number of RRs in the question section. This should normally be just 1.
func (m *Msg) Qdcount(x ...uint16) uint16 {
	if len(m.octets) < 6 {
		return 0
	}
	if len(x) == 0 {
		return binary.BigEndian.Uint16(m.octets[4:])
	}
	binary.BigEndian.PutUint16(m.octets[4:], x[0])
	return 0
}

// Ancount returns the number of RRs in the answer section.
func (m *Msg) Ancount(x ...uint16) uint16 {
	if len(m.octets) < 8 {
		return 0
	}
	if len(x) == 0 {
		return binary.BigEndian.Uint16(m.octets[6:])
	}
	binary.BigEndian.PutUint16(m.octets[6:], x[0])
	return 0
}

// Nscount returns the number of RRs in the authority section.
func (m *Msg) Nscount(x ...uint16) uint16 {
	if len(m.octets) < 10 {
		return 0
	}
	if len(x) == 0 {
		return binary.BigEndian.Uint16(m.octets[8:])
	}
	binary.BigEndian.PutUint16(m.octets[8:], x[0])
	return 0
}

// Arcount returns the number of RRs in the additional section. Note that the Pscount is subtracted from this
// when a value is returned.
func (m *Msg) Arcount(x ...uint16) uint16 {
	if len(m.octets) < 12 {
		return 0
	}
	if len(x) == 0 {
		return binary.BigEndian.Uint16(m.octets[10:]) - m.ps
	}
	binary.BigEndian.PutUint16(m.octets[10:], x[0])
	return 0
}

// Pscount returns the numer of RR in the - not existing on the wire) pseudo section.
func (m *Msg) Pscount(x ...uint16) uint16 {
	if len(x) == 0 {
		return m.ps
	}
	m.ps = x[0]
	return 0
}

// jumpsection jumps rrs RRs through octects. The returned offset is the start of the next section.
func jumpsection(octects []byte, off, rrs int) int {
	for range rrs {
		j := jump(octects, off)
		if j == 0 {
			return 0
		}
		off += j
	}
	return off
}

// jump jumps from octets[off:] to the end of the RR that should start on off. If something is wrong 0 is returned.
func jump(octets []byte, off int) int {
	for {
		c := int(octets[off])
		off++
		switch c & 0xC0 {
		case 0x00:
			if c == 0x00 { // end of the name
				if off+10 > len(octets) {
					return 0
				}
				rdlength := binary.BigEndian.Uint16(octets[off+8:])
				return off + int(rdlength) + 1
			}
			off += c
		case 0xC0:
			// pointer
			off++
		default:
			// 0x80 and 0x40 are reserved
			return 0
		}
		if off > len(octets) {
			return 0
		}
	}
}
