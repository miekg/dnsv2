package dns

import (
	"encoding/binary"
	"fmt"
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
	// Even though the protocol allows multiple questions, in practice only 1 is allowed, this package enforces that
	// convention. After setting any RR, Buf may be written to the wire as it will contain a valid DNS message.
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
	// In this package the question section's RR is handled as a normal RR, but without any rdata - which is an
	// actual RR ever since dynamic updates (RFC xxxx) have been defined.
	Msg struct {
		Buf []byte // Buf is the message as read from the wire or as created.

		// indices of section starts (0 means no RRs in that section), this is updated as we read from the
		// message. On every RR read, this advances to the index of the next RR.
		r [4]uint16

		// reader count for each section, updated as we read from the message. Writer count is in the header.
		count [4]uint16

		// can be filed when indexing? Or remove??
		compression map[string]*int // name to index for the compression pointers
	}

	// Section signifies a message's section. Four sections are defined (in order): Qd, An, Ns, and Ar.
	Section int
)

// These are the sections in a Msg.
const (
	Qd Section = iota // Query Domain/Data (count)
	An                // Answer (count)
	Ns                // Ns (count)
	Ar                // Additional Resource (count)
)

// NewMsg returns a pointer to a new Msg. Optionally a buffer can be given here, NewMsg will not allocate a buffer on
// behalf of the caller, it will enlarge a buffer (when given and the need arises).
func NewMsg(buf ...[]byte) *Msg {
	m := new(Msg)
	if len(buf) > 1 {
		m.Buf = buf[0]
	}
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
		binary.BigEndian.PutUint16(m.Buf[4:], i)
	case An:
		binary.BigEndian.PutUint16(m.Buf[6:], i)
	case Ns:
		binary.BigEndian.PutUint16(m.Buf[8:], i)
	case Ar:
		binary.BigEndian.PutUint16(m.Buf[10:], i)
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

// SetRR adds RR's wireformat to the msg m in the specified section. As we build the message RR by RR, you can't go back
// to add to a previous section (although technically you can alter the counts to make that happen in specific cases).
// Any RR can be used to set the question section; it will then just use the name, type and class and ignore the rest.
func (m *Msg) SetRR(s Section, rr RR) error {
	if s == Qd {
		if m.Count(Qd) == 1 {
			return fmt.Errorf("error section already contains data")
		}
		copy(m.Buf[12+1:], Bytes(rr))
		m.SetCount(Qd, 1)
		return nil
	}
	// compression!
	m.Buf = append(m.Buf, Bytes(rr)...)
	return nil
}

// RR returns the next RR from the specified section. If none are found, nil is returned. If there is an error, a
// partial RR may be returned. When first called a message will be walked to find the indices of the sections.
func (m *Msg) RR(s Section) (RR, error) {
	if m.r[Qd] == 0 { // must be 12 after a call to index
		m.index()
	}

	i := int(m.r[s])
	if i == 0 { // an empty message after being index can still have no RRs in this section
		return nil, nil
	}

	if m.count[s] >= m.Count(s) { // section drained
		return nil, nil
	}

	println("I", i)
	fmt.Printf("%v\n", m.Buf[i:])
	name, i, err := m.name(i)
	if err != nil {
		return nil, err
	}

	fmt.Printf("NAME %s %#v\n", name, name)
	println(i, i)
	// we're after the name, now we have type class and ttl, from type we create the correct RR.
	fmt.Printf("%v\n", m.Buf[i:])
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

	fmt.Printf("%v\n", m.Buf[i:])
	// Class
	rr.Hdr().Class[0], rr.Hdr().Class[1] = m.Buf[i], m.Buf[i+1]
	fmt.Printf("CLASS %+v\n", rr.Hdr().Class)

	// if in question section bail out here, as these are no further options.
	if s == Qd {
		m.count[s] = 1
		return rr, nil
	}

	i += 2
	// TTL
	ttl := binary.BigEndian.Uint32(m.Buf[i:])
	println("TTL:", ttl)
	println(m.Buf[i], m.Buf[i+1], m.Buf[i+2], m.Buf[i+3])
	rr.Hdr().TTL[0] = m.Buf[i]
	rr.Hdr().TTL[1] = m.Buf[i+1]
	rr.Hdr().TTL[2] = m.Buf[i+2]
	rr.Hdr().TTL[3] = m.Buf[i+3]
	println(rr.Hdr().TTL.String())
	i += 4
	// Rdata length
	rdl := int(binary.BigEndian.Uint16(m.Buf[i:]))
	i += 2
	println("RDL", rdl)
	if err := rr.Write(m.Buf[i : i+rdl]); err != nil {
		return rr, err
	}
	// lala overflow - or make ints in Msg as well?
	m.r[s] = uint16(i + 1 + rdl) // +1 ??
	m.count[s]++
	return rr, nil
}

// index walks through the message and saves the indices of where the sections start.
func (m *Msg) index() {
	start := 12
	m.r[Qd] = 12
	start = m.skipName(start) + 4 // question section
	println("index start", start)
	for s := An; s <= Ar; s++ {
		c := m.Count(s)
		if c == 0 {
			continue
		}
		m.r[s] = uint16(start)
		for r := uint16(0); r < c; r++ {
			start = m.skipRR(start)
		}
	}
}

// skipName returns the index after the skipped name, so either the 00 label or the index of the pointer value.
func (m *Msg) skipName(offset int) int {
	i := offset
	for i < len(m.Buf) {
		j := uint8(m.Buf[i])
		switch {
		case j == 0:
			return i
		case j&0xC0 == 0xC0:
			// next octet contains (rest of) the pointer value.
			return i + 1
		}
		i += int(j) + 1
	}
	return 0
}

// skipRR skips the RR that should start at offset, the returned offset is positioned on the last octect of this RR.
// 0 is return when we overflow the length of m.Buf.
func (m *Msg) skipRR(offset int) int {
	i := m.skipName(offset)
	if i == 0 {
		return 0
	}
	// advance i to next octet afer name + rest of junk
	i++
	// for normal RR, we have type, class and TT 2, 2, 4), then we find rdlength (2)
	i += 8
	if i > len(m.Buf) {
		return 0
	}
	rdl := int(binary.BigEndian.Uint16(m.Buf[i:]))
	i += 1 + rdl
	println("rdl", rdl)
	if i >= len(m.Buf) {
		return 0
	}
	return i // last octet
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
