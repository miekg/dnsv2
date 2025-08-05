// Package dnswire deals with the encoding from and to the wire.
package dnswire

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

type (
	Type  uint16 // Type is an RR type.
	TTL   int32  // TTL is the time to live in seconds of an RR(set).
	Class uint16 // Class is a DNS class.
	Name  []byte // Name is a (uncompressed) domain name.
)

type (
	Opcode uint8  // Opcode is the Opcode of a DNS message.
	Rcode  uint16 // Rcode is a 12 bit value if we take the extended rcode into account (See RFC 6891)
)

type (
	Uint16 uint16 // Uint16 is a 2 octet value.
	Uint32 uint32 // Uint32 is a 4 octet value.
	Uint48 uint64 // Uint48 is a 6 octet value. Only used in the [TSIG] RR.
)

func (i Uint16) String() string { return strconv.FormatUint(uint64(i), 10) }

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
			s.WriteString(".")
			return s.String()
		}
	}
	// haven't seen 00 ending...?
	s.WriteString(".")
	return s.String()
}

func (t Type) String() string {
	s, ok := typeToString[uint16(t)]
	if ok {
		return s
	}
	return fmt.Sprintf("TYPE%d", int(t))
}

func (c Class) String() string {
	s, ok := classToString[uint16(c)]
	if ok {
		return s
	}
	return fmt.Sprintf("CLASS%d", int(c))
}

func (t TTL) String() string { return strconv.FormatInt(int64(t), 10) }

// classToString is a maps Classes to strings for each class wire type.
var classToString = map[uint16]string{
	1:   "IN",
	2:   "CS",
	3:   "CH",
	4:   "HS",
	254: "NONE",
	255: "ANY",
}

// Marshal encodes s into a DNS encoded domain. It can deal with fully and non-fully qualified names.
// Although in the later case it allocates a new string by adding the final dot. \. is allowed to escape a
// dot.
func (n Name) Marshal(s string) Name {
	// TODO: ugly API? dnswire.Name.Marshal("....") to get something.
	if s == "." {
		n = []byte{0}
		return n
	}

	// check if name starts with a . (so the i-1 check below will never crash)
	if s[len(s)-1] != '.' {
		s += "."
	}

	name := make([]byte, 0, 32) // 32 enough for most names, will be slower
	start := 0
	for i := range len(s) {
		if s[i] == '.' && s[i-1] != '\\' {
			l := i - start
			name = append(name, byte(l&0x3F))
			name = append(name, s[start:i]...)
			start = i + 1
		}
	}
	name = append(name, byte(0))
	n = name
	return n
}

// JumpName jumps the name that should start on octets[off:] and return the offset right after it.
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
		default:
			return 0
		}
	}
}

// Jump jumps from octets[off:] to the end of the RR that should start on off. If something is wrong 0 is returned.
func Jump(octets []byte, off int) int {
	off = JumpName(octets, off)
	if off == 0 || off+10 > len(octets)-1 { // wrong or too little to reach rdlenght
		return 0
	}
	off += 8
	rdlength := binary.BigEndian.Uint16(octets[off:])
	return off + int(rdlength) + 2 // 2 for starting after rdlength
}

// Extend expands octets at offset with expand bytes.
func Extend(octets []byte, off, expand int) []byte {
	octets = append(octets[:off], append(make([]byte, expand), octets[off:]...)...)
	return octets
}
