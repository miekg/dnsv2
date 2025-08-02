package dns

import (
	"crypto/rand"
	"encoding/binary"

	"github.com/miekg/dnsv2/dnswire"
)

func (m *Msg) Octets(x ...[]byte) []byte {
	if len(x) == 0 {
		return m.octets
	}
	m.octets = x[0]
	return nil
}

// ID by default returns a 16-bit random number to be used as a message id. The number is drawn from a cryptographically secure random number generator.
// This being a variable the function can be reassigned to a custom function. For instance, to make it return a static value for testing:
//
//	dns.ID = func() uint16 { return 3 }
var ID = id

// id returns a 16 bits random number to be used as a message id. The random provided should be good enough.
func id() uint16 {
	var id uint16
	if err := binary.Read(rand.Reader, binary.BigEndian, &id); err != nil {
		panic("dns: reading random id failed: " + err.Error())
	}
	return id
}

// ID sets (with parameter) or reads the ID from the DNS message.
func (m *Msg) ID(x ...uint16) (uint16, error) {
	if len(m.octets) < 12 {
		return 0, ErrBuf
	}
	if len(x) == 0 {
		return binary.BigEndian.Uint16(m.octets[0:]), nil
	}
	binary.BigEndian.PutUint16(m.octets[0:], x[0])
	return 0, nil
}

// Question returns the question section of a DNS message. The qdcount must be set to the expected number of RRs (usually 1 for this section).
func (m *Msg) Question() (Section, error) {
	// The question sections starts a offset 12. There is not a complete RR here, but only name, qtype and
	// class. The RFC says it should only be 1 of those, but multiple may be present, we don't care.
	start := 12
	if len(m.octets) < 12 {
		return Section{}, ErrBuf
	}
	end := jumprrs(m.octets, start, int(m.Qdcount()))
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

// jumprrs jumps rrs RRs through octets. The returned offset is just after the last RR.
func jumprrs(octects []byte, off, rrs int) int {
	for range rrs {
		j := dnswire.Jump(octects, off)
		if j == 0 {
			return 0
		}
		off += j
	}
	return off
}
