package dns

import (
	"encoding/binary"
	"fmt"

	"github.com/miekg/dnsv2/dnswire"
)

type (
	// Msg is a DNS message which is used in the query and the response. It's defined as follows:
	//
	//   +---------------------+
	//   |        Header       |
	//   +---------------------+
	//   |       Question      | the question for the name server
	//   +---------------------+
	//   |        Answer       | RRs answering the question
	//   +---------------------+
	//   |      Authority      | RRs pointing toward an authority
	//   +---------------------+
	//   |      Additional     | RRs holding additional information
	//   +---------------------+
	//
	// Even though the protocol allows multiple questions, in practice only 1 is allowed, this package enforces // that convention.
	// After setting any RR, Buf may be written to the wire as it will contain a valid DNS message.
	//
	// The header is defined as follows:
	//                                    1  1  1  1  1  1
	//      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
	//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	//    |                      ID                       |
	//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	//    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
	//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	//    |                    QDCOUNT                    |
	//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	//    |                    ANCOUNT                    |
	//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	//    |                    NSCOUNT                    |
	//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	//    |                    ARCOUNT                    |
	//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	//
	Msg struct {
		buf         []byte         // buf is the msg buffer as created or recieved from the wire
		rindex      int            // reader index.
		rs          Section        // current section we're reading from
		windex      int            // writer index.
		ws          Section        // current section we're writing from
		compression map[string]int // name to index for the compression pointers
	}

	Section int
)

// These are the sections in Msg.
const (
	Qd Section = iota // Query Domain/Data (count)
	An                // Answer (count)
	Ns                // Ns (count)
	Ar                // Additional resource (count)
)

func NewMsg(buf []byte) *Msg {
	m := new(Msg)
	m.buf = buf
	return m
}

// Rcode is a function
func (m *Msg) Rcode() {

}

func (m *Msg) SetRcode() {}

func (m *Msg) SetCount(s Section, i uint16) {
	switch s {
	case Qd:
		dnswire.Uint16(i, m.buf[4:])
	case An:
		dnswire.Uint16(i, m.buf[6:])
	case Ns:
		dnswire.Uint16(i, m.buf[8:])
	case Ar:
		dnswire.Uint16(i, m.buf[10:])
	}
}

func (m *Msg) Count(s Section) uint16 {
	switch s {
	case Qd:
		return binary.BigEndian.Uint16(m.buf[4:])
	case An:
		return binary.BigEndian.Uint16(m.buf[6:])
	case Ns:
		return binary.BigEndian.Uint16(m.buf[8:])
	case Ar:
		return binary.BigEndian.Uint16(m.buf[10:])
	}
	return 0
}

// Reset resets the message m, so it can be used again.
func (m *Msg) Reset() {

}

func (m *Msg) Bytes() []byte { return m.buf[:m.windex+1] }

// SetRR adds RR's wireformat to the msg m in the specified section. As we build the message layer for layer, the ordering
// is important. It needs to be done in the order as specified on the Msg struct.
func (m *Msg) SetRR(s Section, rr RR) error {
	if s < m.ws {
		return fmt.Errorf("bla")
	}
	if s == Qd {
		if m.Count(Qd) == 1 {
			return fmt.Errorf("bla")
		}
		switch rr.(type) {
		case *Question:
			break // ok
		default:
			return fmt.Errorf("bla")
		}
		n := copy(m.buf[12+1:], Bytes(rr))
		m.windex = 12 + n
		m.SetCount(Qd, 1)
		m.ws = Qd
		return nil
	}

	n := copy(m.buf[m.windex+1:], Bytes(rr))
	m.windex += n
	m.ws = s
	m.SetCount(s, m.Count(s)+1)
	return nil
}

// RR returns the next RR from the specified section. If none are found, nil is returned.
// On succesfull return the reader index is set to the next RR, if the read failed it's is not moved.
// An partial RR maybe returned.
func (m *Msg) RR(s Section) (RR, error) {
	// Finding RRs can only be done by walking the message and keeping track of where you are. After the Msg's header you'll
	// need to:
	//
	// * track each domain name, until a pointer or a 00 label
	// * add the type (2), class (2), ttl (4), until you hit the rdata length (2)
	// * use the length to jump to the next RR.

	if m.rindex == 0 {
		m.rindex = 12
	}
	i := m.skipName(m.rindex + 1)
	if i == 0 {
		return nil, fmt.Errorf("failed to find end of name")
	}
	// we're after the name, now we have type class and ttl, from type we create the correct RR.
	tpy := Type{m.buf[i], m.buf[i+1]}
	println("TYPE:", tpy.String())
	rrfunc, ok := typeToRR[tpy]
	if !ok {
		// unknown RR
		println("UNKNOWN RR", tpy[0], tpy[1])
		return nil, fmt.Errorf("bla")
	}
	// buf to use!!! need len(to figure out length first), means jumping the message.
	// Name
	rr := rrfunc()
	// rindex : i+1 is the name (compression!!!)
	copy(rr.Hdr().Name, m.buf[m.rindex:i])
	i++
	fmt.Printf("NAME %+v\n", rr.Hdr().Name)
	// Class
	rr.Hdr().Class[0], rr.Hdr().Class[0] = m.buf[i], m.buf[i+1]
	i++
	println("CLASS", i)
	// TTL
	rr.Hdr().TTL[0] = m.buf[i+1]
	rr.Hdr().TTL[1] = m.buf[i+2]
	rr.Hdr().TTL[2] = m.buf[i+3]
	rr.Hdr().TTL[3] = m.buf[i+4]
	println(rr.Hdr().TTL.String())
	i += 4
	// Rdata length
	rdl := binary.BigEndian.Uint16(m.buf[i+1:])
	i += 2
	println("RDL", rdl)
	err := Write(rr, m.buf[i+1:i+1+int(rdl)])
	if err != nil {
		return rr, err
	}
	m.rindex = i + 1 + int(rdl)
	return rr, nil
}

// skipName return the index of where the domain name ended. This is usually on the 0x00 label, or otherwise on a pointer 0xC0 label.
// off must be the beginning of the name.
func (m *Msg) skipName(off int) int {
	// TODO handle compression pointer.
	i := off
	for {
		j := uint8(m.buf[i])
		println(i, j)
		i += int(j) + 1
		if j == 0 {
			return i
		}
		if i > len(m.buf) {
			return 0
		}
	}
}

// func (m *Msg) Walk()
