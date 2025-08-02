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

// QR sets or returns the QR header bit from the message, this returns true if the Msg is a response.
func (m *Msg) QR(x ...bool) (bool, error) {
	const _QR = 1 << 7 // query/response (response=1)
	if len(m.octets) < 12 {
		return false, ErrBuf
	}
	if len(x) == 0 {
		qr := m.octets[0] & _QR
		return qr == 1, nil
	}

	// clear or set
	if x[0] { // response
		m.octets[0] |= _QR
	} else {
		m.octets[0] &= _QR // wrong this resets everything, need xor or something.
	}

	return false, nil
}

// Opcode sets or returns the opcode from the DNS message.
func (m *Msg) Opcode(x ...dnswire.Opcode) (dnswire.Opcode, error) {
	return OpcodeQuery, nil
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
// If a parameter is given, the section will be set in the message as the question section, the qdcount will be updated appropriately.
func (m *Msg) Question(x ...*Section) *Section {
	if len(x) == 0 {
		// The question sections starts a offset 12. There is not a complete RR here, but only name, qtype and
		// class. The RFC says it should only be 1 of those, but multiple may be present, we don't care.
		start := 12
		if len(m.octets) < 12 {
			return nil
		}
		end := jumprrs(m.octets, start, int(m.Qdcount()))
		return &Section{which: Question, msg: m, octets: m.octets[start:end]}
	}
	// TODO: what if we already have something here? Cut it out and replace...?
	if m.octets == nil {
		m.octets = make([]byte, 12)
		m.octets = append(m.octets, x[0].octets...)
		l := x[0].Len()
		m.Qdcount(uint16(l))
	}
	return nil
}

func (m *Msg) Answer() *Section {
	return &Section{which: Answer}
}

func (m *Msg) Ns() *Section {
	return &Section{which: Ns}
}

func (m *Msg) Extra() *Section {
	return &Section{which: Extra}
}

func (m *Msg) Pseudo() *Section {
	return &Section{which: Pseudo}
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

// Compress performs DNS name compression on the entire DNS message. After this you should not add more RRs to
// the message because this messes up the compression pointers (unless you add at the end, either the
// Additional or Pseudo section.
func (m *Msg) Compress() {
	// todo
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
