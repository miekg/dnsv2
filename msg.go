package dns

import (
	"crypto/rand"
	"encoding/binary"

	"github.com/miekg/dnsv2/dnswire"
)

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

func allocHeader(m *Msg) {
	if len(m.octets) < MsgHeaderLen {
		m.octets = make([]byte, MsgHeaderLen)
	}
}

// ID sets (with parameter) or reads the ID from the DNS message.
func (m *Msg) ID(x ...uint16) (uint16, error) {
	allocHeader(m)
	if len(x) == 0 {
		return binary.BigEndian.Uint16(m.octets[0:]), nil
	}
	binary.BigEndian.PutUint16(m.octets[0:], x[0])
	return 0, nil
}

// If Octets does not have a parameter it returns the wire encoding octets for this message. If a parameter is
// given the octets are written to the message.
func (m *Msg) Octets(x ...[]byte) []byte {
	if len(x) == 0 {
		return m.octets
	}
	m.octets = x[0]
	return nil
}

// QR sets or returns the QR header bit from the message, this returns true if the Msg is a response.
func (m *Msg) QR(x ...bool) (bool, error) {
	const _QR = 1 << 7 // query/response (response=1)
	allocHeader(m)

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
	allocHeader(m)
	return OpcodeQuery, nil
}

// Payload sets (or reads) the EDNS0 UDP payload size. When setting either the existing OPT record's data will
// be overriden or a new one is added. The read will fail when there is no OPT record present.
func (m *Msg) Payload(x ...dnswire.Uint16) (dnswire.Uint16, error) {
	// opt.Class(dnswire.Class(x))
	return 0, nil
}

// DO sets or reads the EDNS0 DO (DNSSEC OK) flag. When setting either the existing OPT record's data will be
// overridden or a new one is added. The read will fail when there is no OPT record present.
func (m *Msg) DO(x ...bool) (bool, error) {
	return false, nil
}

// Question returns the question section of a DNS message.
func (m *Msg) Question() *Question {
	if len(m.octets) < MsgHeaderLen {
		return nil
	}
	// check question count?
	end := jumpquestion(m.octets)
	return &Question{m, section{start: MsgHeaderLen, end: end}}
}

// Answer reads the answer section.
func (m *Msg) Answer() *Answer {
	if len(m.octets) < MsgHeaderLen {
		return nil
	}
	start := jumpquestion(m.octets)
	end := jumprrs(m.octets, start, int(m.Ancount()))
	return &Answer{m, section{start: start, end: end}}
}

func (q *Question) Octets() []byte { return q.Msg.octets[q.start:q.end] }
func (a *Answer) Octets() []byte   { return a.Msg.octets[a.start:a.end] }
func (n *Ns) Octets() []byte       { return n.Msg.octets[n.start:n.end] }
func (e *Extra) Octets() []byte    { return e.Msg.octets[e.start:e.end] }
func (p *Pseudo) Octets() []byte   { return p.Msg.octets[p.start:p.end] }

// Ns reads or sets the authority section.
func (m *Msg) Ns(x ...*Ns) *Ns { return &Ns{} }

// Extra reads or sets the additional section.
func (m *Msg) Extra(x ...*Extra) *Extra { return &Extra{} }

// Extra reads or sets the pseudo section.
func (m *Msg) Pseudo(x ...*Pseudo) *Pseudo { return &Pseudo{} }

// Qdcount returns the number of RRs in the question section. This should normally be just 1.
func (m *Msg) Qdcount(x ...uint16) uint16 {
	if len(m.octets) < MsgHeaderLen {
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
	if len(m.octets) < MsgHeaderLen {
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
	if len(m.octets) < MsgHeaderLen {
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
	if len(m.octets) < MsgHeaderLen {
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
func jumprrs(octets []byte, off, rrs int) int {
	for range rrs {
		j := dnswire.Jump(octets, off)
		if j == 0 {
			return 0
		}
		off = j
	}
	return off
}

// jumpquestion jumps "rr" in the question section.
func jumpquestion(octets []byte) int {
	j := dnswire.JumpName(octets, MsgHeaderLen)
	if j == 0 || j+4 > len(octets) {
		return 0
	}
	return j + 4
}
