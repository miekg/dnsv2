// Package dnswire deals with the encoding from and to wire encoding. In Go these functions are usually called
// Marshal and Unmarshal.
package dnswire

import (
	"bytes"
	"encoding/binary"
	"strings"
)

type (
	Type  uint16 // Type is an RR type.
	TTL   int32  // TTL is the time to live of an RR(set).
	Class uint16 // Class is a DNS class.
	Name  []byte // Name is a domain name.
)

type Opcode uint8

func (n Name) String() string {
	if len(n) == 1 && n[0] == 0 {
		return "."
	}

	s := strings.Builder{}
	off := 0

	for {
		if off > len(n)-1 {
			break
		}

		c := int(n[off])
		off++
		switch c & 0xC0 {
		case 0x00:
			if c == 0x00 { // end of the name
				s.WriteString(".")
				return s.String()
			}
			if off > 2 { // don't start with a dot
				s.WriteString(".")
			}
			s.Write(n[off : off+c])
			off += c

		case 0xC0:
			// pointer, shouldn't happen here
			off++
			s.WriteString(".")
		}
	}
	// haven't seen 00 ending...?
	s.WriteString(".")
	return s.String()
}

// Marshal encodes s into a DNS encoded domain. It can deal with fully and non-fully qualified names.
// Although in the later case it allocates a new string by adding the final dot for you.
// This also takes care of all the esoteric encoding allowed like \DDD and \. to escape a dot.
func (n Name) Marshal(s string) Name {
	if s == "." {
		n = []byte{0}
		return n
	}

	if s[len(s)-1] != '.' {
		s += "."
	}

	name := bytes.NewBuffer(make([]byte, 0, 32))
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			l := i - start
			name.WriteByte(byte(l & 0x3F))
			name.WriteString(s[start:i])

			start = i + 1
		}
	}
	name.WriteByte(0)
	n = name.Bytes()
	return n
}

// JumpName jumps the name that should start un octets[off:] and return the offset right after it.
func JumpName(octets []byte, off int) int {
	for {
		if off > len(octets)-1 {
			return 0
		}
		c := int(octets[off])
		off++
		switch c & 0xC0 {
		case 0x00:
			if c == 0x00 { // end of the name
				return off
			}
			off += c
		case 0xC0:
			// pointer, end of the name, we don't need to follow it
			return off + 1
		}
	}
}

// Jump jumps from octets[off:] to the end of the RR that should start on off. If something is wrong 0 is returned.
// The rdlength in the RR must reflect the reality.
func Jump(octets []byte, off int) int {
	off = JumpName(octets, off)
	if off == 0 {
		return 0
	}

	if off+10 > len(octets) {
		return 0
	}
	off += 8
	rdlength := binary.BigEndian.Uint16(octets[off:])
	return off + int(rdlength) + 2 // 2 for starting after rdlength
}

// RR decodes (resolving compression pointers) the RR's from octets, starting at offset off, at this point the
// RR's should start. Octets should coming from the message that holds the RR. This functions returns an
// opaque slice of bytes and the Type of RR.
func RR(octets []byte, off int) ([]byte, Type, int) {
	begin := off

	rr := bytes.NewBuffer(make([]byte, 0, 32)) // [bytes.Buffer] uses a 64 byte buffer, most names aren't that long, cut this in half.
	ptr := 0
Loop:
	for {
		if off > len(octets)-1 {
			return nil, 0, 0
		}
		c := int(octets[off])
		off++
		switch c & 0xC0 {
		case 0x00:
			if c == 0x00 { // end of the name
				rr.WriteByte(0)
				break Loop
			}
			rr.Write(octets[off : off+c])
			off += c
		case 0xC0:
			if ptr++; ptr > 10 { // Every label can be a pointer, so the max is maxlabels.?
				return nil, 0, 0
			}
			c1 := int(octets[off]) // the next octet
			off = ((c^0xC0)<<8 | c1)
		}
	}
	end := Jump(octets, begin)
	if end > len(octets)-1 || end == 0 {
		return nil, 0, 0
	}
	begin = JumpName(octets, begin)
	if begin > end {
		return nil, 0, 0
	}
	t := Type(binary.BigEndian.Uint16(octets[begin:]))
	return rr.Bytes(), t, end
}
