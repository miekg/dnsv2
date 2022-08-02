package dns

import (
	"encoding/binary"
	"fmt"
	"strings"
)

type (
	// Msg is a DNS message which is used in the query and the response. It's defined as follows:
	//
	//   +---------------------+
	//   |        Header       |
	//   +---------------------+
	//   |       Question      | the question for the name server, [Qd].
	//   +---------------------+
	//   |        Answer       | RRs answering the question, [An].
	//   +---------------------+
	//   |      Authority      | RRs pointing toward an authority, [Ns].
	//   +---------------------+
	//   |      Additional     | RRs holding additional information, [Ar].
	//   +---------------------+
	//
	// A Msg allows RRs to be added (in order) or retrieved (in order per section, but each section can accessed in
	// any order).
	//
	// Even though the protocol allows multiple questions, in practice only 1 is allowed, this package enforces that
	// convention. After setting any RR, Buf may be written to the wire as it will contain a valid DNS message.
	// In this package the question section's RR is handled as a normal RR, just without any rdata - as is also done
	// in dynamic updates (RFC 2136).
	//
	// The message header is defined as follows:
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
	// If the buffer in Msg is too small it will be resized and creating a message.
	Msg struct {
		Buf []byte // Buf is the message as read from the wire or as created.

		w uint16 // index of last write

		// indices of section starts (0 means no RRs in that section), this is updated as we read from the
		// message. On every RR read, this advances to the index of the next RR.
		r [4]uint16

		// reader count for each section, updated as we read from the message. Writer count is in the header.
		count [4]uint16

		// c is used to apply compression to owner names and a few names in rdata of well known
		// types. The returned uint16 is the target value for the pointer.
		c compression
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
	if len(buf) > 0 {
		m.Buf = buf[0]
	}
	m.w = 12 // after header, needs buf size of at least this.
	m.c = compression{}
	return m
}

// ID returns the message's ID.
func (m *Msg) ID() uint16 { return binary.BigEndian.Uint16(m.Buf[0:]) }

// SetID sets the message to i.
func (m *Msg) SetID(i uint16) { binary.BigEndian.PutUint16(m.Buf[0:], i) }

// Rcode is a function
func (m *Msg) Rcode() {
	// check extended Rcode
}

func (m *Msg) SetRcode() {}

func (m *Msg) Opcode()    {}
func (m *Msg) SetOpcode() {}

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

// SetRR adds rr's wireformat to the message m in the specified section. Any RR can be used to set the question section;
// it will then just use the name, type and class and ignore the
func (m *Msg) SetRR(s Section, rr RR) error {
	c := m.Count(s)
	if s == Qd {
		if c == 1 {
			return &WireError{fmt.Errorf("question section occupied, no room for %s", RRType(rr))}
		}
		m.bytes(s, rr)
		m.SetCount(Qd, 1)
		return nil
	}
	m.SetCount(s, c+1)
	m.bytes(s, rr)
	return nil
}

// RR returns the next RR from the specified section. If none are found, nil is returned. If there is an error, a
// partial RR may be returned. When first called a message will be walked to find the indices of the sections.
func (m *Msg) RR(s Section) (RR, error) {
	if m.r[Qd] == 0 { // must be 12 after a call to index
		err := m.index()
		if err != nil {
			return nil, err
		}
	}

	i := int(m.r[s])
	if i == 0 { // an empty message after being index can still have no RRs in this section
		return nil, nil
	}

	if m.count[s] >= m.Count(s) { // section drained
		return nil, nil
	}

	name, i, err := unpackName(m.Buf, i)
	if err != nil {
		return nil, err
	}

	// we're after the name, now we have type class and ttl, from type we create the correct RR.
	i++
	tpy := Type{m.Buf[i], m.Buf[i+1]}
	rrfunc, ok := typeToRR[tpy]
	if !ok {
		rrfunc = func() RR { return new(Unknown) }
	}
	i += 2

	rr := rrfunc()
	rr.Hdr().Name = name
	if rfc3597, ok := rr.(*Unknown); ok {
		rfc3597.Type = tpy
	}

	// Class
	rr.Hdr().Class[0], rr.Hdr().Class[1] = m.Buf[i], m.Buf[i+1]

	if s == Qd {
		m.count[s]++
		return rr, nil
	}

	i += 2
	// TTL
	rr.Hdr().TTL[0] = m.Buf[i]
	rr.Hdr().TTL[1] = m.Buf[i+1]
	rr.Hdr().TTL[2] = m.Buf[i+2]
	rr.Hdr().TTL[3] = m.Buf[i+3]
	i += 4
	// Rdata length
	rdl := int(binary.BigEndian.Uint16(m.Buf[i:]))
	//	println("RDL", rdl)
	i += 2
	if err := rr.Write(m.Buf, i, rdl); err != nil {
		return rr, err
	}
	// check rdl with returned bytes written.
	// lala overflow - or make ints in Msg as well?
	m.r[s] = uint16(i + rdl)
	m.count[s]++
	return rr, nil
}

func (m *Msg) RRs(s Section) ([]RR, error) {
	rrs := []RR{}
	for rr, err := m.RR(s); rr != nil; rr, err = m.RR(s) {
		if err != nil {
			return rrs, err
		}
		rrs = append(rrs, rr)
	}
	return rrs, nil
}

// index walks through the message and saves the indices of where the sections start.
func (m *Msg) index() error {
	offset := 12
	m.r[Qd] = 12
	if offset = m.skipName(offset); offset == 0 {
		return &WireError{fmt.Errorf("buffer size to small, no owner name found in %s section", Qd.String())}
	}
	offset += 5 // 4 to skip TYPE, CLASS, +1 to land on next RR
	// Answer
	c := m.Count(An)
	if c > 0 {
		m.r[An] = uint16(offset)
		for i := uint16(0); i < c; i++ {
			offset = m.skipRR(offset)
			if offset == 0 {
				return &WireError{fmt.Errorf("buffer size to small, no RR found in %s section", An.String())}
			}
			offset++ // start of next RR
		}
	}
	// Authority
	c = m.Count(Ns)
	if c > 0 {
		m.r[Ns] = uint16(offset)
		for i := uint16(0); i < c; i++ {
			offset = m.skipRR(offset)
			if offset == 0 {
				return &WireError{fmt.Errorf("buffer size to small, no RR found in %s section", Ns.String())}
			}
			offset++ // start of next RR
		}

	}
	// Additional
	c = m.Count(Ar)
	if c > 0 {
		m.r[Ar] = uint16(offset)
	}
	return nil
}

// skipName returns the index after the skipped name, so either the 00 label or the index of the pointer value.
func (m *Msg) skipName(offset int) int {
	// see Name.Next()
	i := offset
	for i < len(m.Buf) {
		j := m.Buf[i]
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

// skipRR skips the RR that should start at offset, the returned offset is positioned on the last octet of this RR.
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
	if i >= len(m.Buf) {
		return 0
	}
	return i // last octet
}

// unpackName return a domain name that should start at offset. Compression pointers are followed, the returned offset is
// positioned on the last octet of the name.
func unpackName(msg []byte, offset int) (Name, int, error) {
	ptr := 0
	ptroffset := 0
	buf := make([]byte, 0, 12) // 12 is random number
	for i := offset; i < len(msg); {
		j := uint8(msg[i])
		switch {
		case j&0xC0 == 0:
			if j == 0 {
				// end of name, if we got here via a pointer we need to return that offset, otherwise
				// the one we've accumulated.
				buf = append(buf, []byte{0}...)
				if ptroffset > 0 {
					return Name(buf), ptroffset, nil
				}
				return Name(buf), offset, nil
			}
			buf = append(buf, msg[i:i+int(j)+1]...)
			i += int(j) + 1
			offset += int(j) + 1
		case j&0xC0 == 0xC0:
			// save position, as we are here in the message, regardless of how maby pointers we follow.
			if ptr++; ptr > 10 {
				return nil, 0, &WireError{fmt.Errorf("too many (>10) compression pointers")}
			}
			j1 := uint8(msg[i+1])
			i = int(j^0xC0) | int(j1)
			if ptroffset == 0 { // the first pointer we follow, ends the wire encoding of this RR.
				ptroffset = offset + 1 // advance octet
			}
		}
	}
	if len(buf) == 0 {
		return nil, offset, &WireError{fmt.Errorf("no owner name found at offset %d", offset)}
	}
	return nil, offset, nil
}

// String returns the text representation of the message m. Note this method _parses_ the message and
// extracts the RRs for printing, this makes it an expensive method. It can also error, in that case the
// empty string is returned. Mostly useful for debugging.
func (m *Msg) String() string {
	b := &strings.Builder{}
	b.WriteString(";; ->>HEADER<<-\n")
	// ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 32123
	b.WriteString(";; flags: bla; ")
	b.WriteString(fmt.Sprintf("%s %d, %s: %d, %s: %d, %s: %d\n", Qd, m.Count(Qd), An, m.Count(An), Ns, m.Count(Ns), Ar, m.Count(Ar)))

	for s := Qd; s <= Ar; s++ {
		if m.Count(s) == 0 {
			continue
		}
		b.WriteString(fmt.Sprintf(";; %s SECTION:\n", s))
		rrs, err := m.RRs(s)
		if err != nil {
			return b.String()
		}
		for _, rr := range rrs {
			if opt, ok := rr.(*OPT); ok {
				b.WriteString(";; EDNS: version: ")
				b.WriteString(fmt.Sprintf("%d", opt.Version()))
				b.WriteString(", flags:; udp: ")
				b.WriteString(fmt.Sprintf("%d\n", opt.Size()))
				continue
			}
			if s == Qd {
				b.WriteString(rr.Hdr().Name.String())
				b.WriteString(" ")
				b.WriteString(rr.Hdr().Class.String())
				b.WriteString(" ")
				b.WriteString(RRType(rr).String())
				b.WriteString("\n")
				continue
			}
			b.WriteString(rr.Hdr().String())
			b.WriteString("\t")
			b.WriteString(rr.String())
			b.WriteString("\n")
		}
		if len(rrs) > 0 && s != Ar {
			b.WriteString("\n")
		}
	}
	return b.String()
}

/*
bytes converts an RR to the format we can use on the wire. The format is described in RFC 1035:

                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                                               /
    /                      NAME                     /
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     CLASS                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TTL                      |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                   RDLENGTH                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    /                     RDATA                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

The wire bytes are directly written into the message. If the buffer is too small it will be resized to fit the RR.
*/
func (m *Msg) bytes(s Section, rr RR) {
	offset := m.w

	i, pointer := m.c.find(rr.Hdr().Name)
	if pointer == 0 {
		if len(rr.Hdr().Name)+int(offset) >= len(m.Buf) {
			m.Buf = append(m.Buf, make([]byte, len(rr.Hdr().Name)+10)...) // + 10 for everything up to rdata
		}

		n := copy(m.Buf[offset:], rr.Hdr().Name)
		offset += uint16(n)
	} else {
		if int(i)+2+int(offset) >= len(m.Buf) { // +2 compression pointer
			m.Buf = append(m.Buf, make([]byte, i+2+10)...) // + 10 for everything up to rdata
		}

		n := copy(m.Buf[offset:], rr.Hdr().Name[:i])
		offset += uint16(n)
		binary.BigEndian.PutUint16(m.Buf[offset+1:], pointer)
		offset += 3
	}

	// don't compress after certain offset, compression pointer can't reach.
	m.c.insert(rr.Hdr().Name, m.w)

	m.Buf[offset+0] = RRType(rr)[0]
	m.Buf[offset+1] = RRType(rr)[1]
	m.Buf[offset+2] = rr.Hdr().Class[0]
	m.Buf[offset+3] = rr.Hdr().Class[1]
	offset += 3

	// return here if question section
	if s == Qd {
		m.w = offset
		return
	}

	m.Buf[offset+1] = rr.Hdr().TTL[0]
	m.Buf[offset+2] = rr.Hdr().TTL[1]
	m.Buf[offset+3] = rr.Hdr().TTL[2]
	m.Buf[offset+4] = rr.Hdr().TTL[3]
	offset += 4

	rdlen := offset // length start
	offset += 2

	l := uint16(0)
	j := offset
	for i := 0; i < rr.Len(); i++ {
		data := rr.Data(i)
		if len(data)+int(j)+1 >= len(m.Buf) {
			m.Buf = append(m.Buf, make([]byte, len(data))...)
		}

		// for compression I need to knows which rdata of which RR is compressible, finite set, so can be done here
		n := copy(m.Buf[j+1:], rr.Data(i))
		j += uint16(n)
		l += uint16(n)
	}
	// write rdlength at correct place
	binary.BigEndian.PutUint16(m.Buf[rdlen+1:], l)

	m.w = j

	return
}
