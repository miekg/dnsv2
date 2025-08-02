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

func (n Name) String() string {
	if len(n) == 1 && n[0] == 0 {
		return "."
	}

	s := strings.Builder{}
	off := 0

	for {
		if off > len(n) {
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
			if off > 2 {
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

type Opcode uint8

// Jump jumps from octets[off:] to the end of the RR that should start on off. If something is wrong 0 is returned.
func Jump(octets []byte, off int) int {
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

// JumpName jumps the name that should start un octets[off:] and return the offset right after it.
func JumpName(octets []byte, off int) int {
	for {
		c := int(octets[off])
		off++
		switch c & 0xC0 {
		case 0x00:
			if c == 0x00 { // end of the name
				return off
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

// RRType returns the RR's type. On error TypeNone is returned.
func RRType(octets []byte, off int) Type {
	off = JumpName(octets, off)
	if off == 0 {
		return 0
	}
	if off+2 > len(octets) {
		return 0
	}
	return Type(binary.BigEndian.Uint16(octets[off:]))
}
