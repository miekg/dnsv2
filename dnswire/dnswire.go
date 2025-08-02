// Package dnswire deals with the encoding from and to wire encoding. In Go these functions are usually called
// Marshal and Unmarshall.
package dnswire

import (
	"bytes"
	"encoding/binary"
)

type (
	Type  uint16 // Type is an RR type.
	TTL   int32  // TTL is the time to live of an RR(set).
	Class uint16 // Class is a DNS class.
	Name  []byte // Name is a domain name.
)

func (n Name) String() string {
	return "this-should-be-a-string"
}

func (n Name) Marshal(s string) {
	name := bytes.NewBuffer(make([]byte, 32)) // [bytes.Buffer] uses a 64 byte buffer, most names aren't that long, cut this in half.

	for i := 0; i < len(s); i++ {
		c := s[i]

	}

	n = name.Bytes()
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
				return off + 1 // also skip this nil byte
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
