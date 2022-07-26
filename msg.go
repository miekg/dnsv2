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
		Buf []byte // Buf is the message as read from the wire or as created.

		r       [4]uint16 // indices of section starts (0 means no such section), this is updated as we read from the message.
		AnCount uint16    // reader count for An section, writer count is in msg header.
		NsCount uint16    // reader count for Ns section, writer count is in msg header.
		ArCount uint16    // reader count for Ar section, writer count is in msg header.

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
	m.Buf = buf
	return m
}

// Rcode is a function
func (m *Msg) Rcode() {
	// check extended Rcode

}

func (m *Msg) SetRcode() {}

func (m *Msg) SetCount(s Section, i uint16) {
	switch s {
	case Qd:
		dnswire.Uint16(i, m.Buf[4:])
	case An:
		dnswire.Uint16(i, m.Buf[6:])
	case Ns:
		dnswire.Uint16(i, m.Buf[8:])
	case Ar:
		dnswire.Uint16(i, m.Buf[10:])
	}
}

func (m *Msg) Count(s Section) uint16 {
	switch s {
	case Qd:
		return binary.BigEndian.Uint16(m.Buf[4:])
	case An:
		return binary.BigEndian.Uint16(m.Buf[6:])
	case Ns:
		return binary.BigEndian.Uint16(m.Buf[8:])
	case Ar:
		return binary.BigEndian.Uint16(m.Buf[10:])
	}
	return 0
}

/*
// SetRR adds RR's wireformat to the msg m in the specified section. As we build the message RR by RR, you can't go back to
// add to a previous section (although technically you can alter the counts to make that happen in specific cases). Any RR
// can be used to set the question section; it will then just use the name, type and class and ignore the rest.
func (m *Msg) SetRR(s Section, rr RR) error {
	if s == Qd {
		if m.Count(Qd) == 1 {
			return fmt.Errorf("error section already contains data")
		}
		// don't use bytes, but extract ourselves.
		n := copy(m.Buf[12+1:], Bytes(rr))
		m.windex = 12 + n
		m.SetCount(Qd, 1)
		m.ws = Qd
		return nil
	}

	n := copy(m.Buf[m.windex+1:], Bytes(rr))
	m.windex += n
	m.ws = s
	m.SetCount(s, m.Count(s)+1)
	return nil
}
*/

// RR returns the next RR from the specified section. If none are found, nil is returned. If there is
// an error, a partial RR may be returned.
func (m *Msg) RR(s Section) (RR, error) {
	if m.r[s] == 0 {
		return nil, fmt.Errorf("msg m is not indexed")
	}

	println("start", m.r[s])
	i := int(m.r[s])
	fmt.Printf("%v\n", m.Buf[i:])
	name, i, err := m.name(i)
	if err != nil {
		return nil, err
	}
	println("next offset", i, "read", i-int(m.r[s]))

	// we're after the name, now we have type class and ttl, from type we create the correct RR.
	tpy := Type{m.Buf[i], m.Buf[i+1]}
	println("TYPE:", tpy.String())
	rrfunc, ok := typeToRR[tpy]
	if !ok {
		// unknown RR
		println("UNKNOWN RR", tpy[0], tpy[1])
		return nil, fmt.Errorf("bla")
	}
	i += 2

	rr := rrfunc()
	rr.Hdr().Name = name
	fmt.Printf("NAME %s %#v\n", name, name)

	fmt.Printf("%v\n", m.Buf[i:])
	// Class
	rr.Hdr().Class[0], rr.Hdr().Class[1] = m.Buf[i], m.Buf[i+1]
	fmt.Printf("CLASS %+v\n", rr.Hdr().Class)
	i += 2
	// TTL
	ttl := binary.BigEndian.Uint32(m.Buf[i:])
	println("TT", ttl)
	println(m.Buf[i], m.Buf[i+1], m.Buf[i+2], m.Buf[i+3])
	rr.Hdr().TTL[0] = m.Buf[i]
	rr.Hdr().TTL[1] = m.Buf[i+1]
	rr.Hdr().TTL[2] = m.Buf[i+2]
	rr.Hdr().TTL[3] = m.Buf[i+3]
	println(rr.Hdr().TTL.String())
	i += 4
	// Rdata length
	rdl := binary.BigEndian.Uint16(m.Buf[i+1:])
	i += 2
	println("RDL", rdl)
	/*
		err := Write(rr, m.Buf[i+1:i+1+int(rdl)])
		if err != nil {
			return rr, err
		}
		m.r[s] = i + 1 + int(rdl)
		return rr, nil
	*/
	return nil, nil
}

// index walks through the message and saves the indices of where the defined sections start.
func (m *Msg) index() {
	start := 12
	m.r[Qd] = 12
	start += m.skipName(start) + 4 // question section
	println("index start", start)
	for s := An; s <= Ar; s++ {
		c := m.Count(s)
		if c == 0 {
			continue
		}
		m.r[s] = uint16(start)
		for r := uint16(0); r < c; r++ {
			start += m.skipRR(start)
		}
	}
}

// skipName return the index of where the domain name ended. This is usually on the 0x00 label, or otherwise on a pointer 0xC0 label.
// off must be the beginning of the name.
func (m *Msg) skipName(offset int) int {
	i := offset
	for i < len(m.Buf) {
		j := uint8(m.Buf[i])
		switch {
		case j == 0:
			return i
		case j&0xC0 == 0xC0:
			return i
		}
		i += int(j) + 1
	}
	if i == offset {
		return i
	}
	return i + 1
}

// skipRR skips the RR start should start at offset, the returned offset is positioned on the first octet of the next RR.
// 0 is return when we overflow the length of m.Buf.
func (m *Msg) skipRR(offset int) int {
	// must be at beginning of RR. If begining of Question offset = 12
	i := m.skipName(offset)
	if offset == 12 {
		return i + 3 // type + class
	}
	// for normal RR, we have TTL, then rdlength
	i += 4
	rdlen := binary.BigEndian.Uint16(m.Buf[i:])
	if i+1+int(rdlen) > len(m.Buf) {
		return 0
	}
	return i + int(rdlen) + 1
}

// returned int is next offset.
func (m *Msg) name(offset int) (Name, int, error) {
	ptr := 0
	buf := make([]byte, 0, 12) // 12 is random number
	for i := offset; i < len(m.Buf); {
		j := uint8(m.Buf[i])
		println("J", j)
		switch {
		case j&0xC0 == 0:
			if j == 0 {
				buf = append(buf, []byte{0}...)
				return Name(buf), offset + 1, nil
			}
			buf = append(buf, m.Buf[i:i+int(j)+1]...)
			println(string(buf))
			i += int(j) + 1
			offset += int(j) + 1
		case j&0xC0 == 0xC0:
			println("POINTER")
			// save position, as we are here in the message, regardless of how
			// we follow pointers.
			if ptr++; ptr > 10 {
				return nil, 0, fmt.Errorf("too many compression pointers")
			}
			j1 := uint8(m.Buf[i+1])
			i = int(j^0xC0) | int(j1)
			offset += 2 // advance 2 octets
			println("points to", i)
		}
	}
	if len(buf) == 0 {
		return nil, offset, fmt.Errorf("nothing found")
	}
	return nil, offset + 1, nil
}
