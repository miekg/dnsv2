package dns

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/miekg/dnsv2/dnswire"
)

// Compress performs DNS name compression on the entire message. After this you should not add more RRs to
// the message because this messes up the compression pointers (unless you add at the end, either the
// Additional or Pseudo section).
func (m *Msg) Compress() {
	// todo
}

// Decompress resolves all compression pointers in the message.
func (m *Msg) Decompress() {
	// We walk the entire message and track where each RR begins. Then we walk this list backwards and resolve
	// each compression pointer and replace those bytes with the expanded name.
	//
	// For RRs that can have compressed rdata we basically do the same, but then we also need to adjust the
	// rdlength uint16 in the message to adjust for the new size.

	offsets := make([]int, 0, 7) // 7: conservative guess on how many RR we expect in the common case.
	offsets = append(offsets, MsgHeaderLen)

	j := dnswire.Jump(m.octets, offsets[0])
	if j == 0 {
		return
	}
	offsets = append(offsets, j+4) // question name + type (2) + class (2)
	i := 1                         // start of the RR after the question section.
	for {
		j = dnswire.Jump(m.octets, offsets[i])
		if j == 0 {
			break
		}
		offsets = append(offsets, j)
		i++
	}
	fmt.Printf("%v\n", offsets)

	name := bytes.NewBuffer(make([]byte, 0, 32)) // [bytes.Buffer] uses a 64 byte buffer, most RRs aren't that long, cut this in half.

	// We assume the question section is not compressed, consists only out of 1 question.
	for i := len(offsets) - 1; i > 0; i-- {
		off := offsets[i]

		// rrtype is offset + Name + 0
		typeoffset := dnswire.JumpName(m.octets, off)
		rrtype := dnswire.Type(binary.BigEndian.Uint16(m.octets[typeoffset:]))
		println("type:", rrtype.String())
		rdlengthoffset := typeoffset + 8
		rdlength := binary.BigEndian.Uint16(m.octets[rdlengthoffset:])
		println("rdlength:", rdlength)

		// if the new name is longer, we have something expanded, otherwise continue
		decompress(m.octets, off, name)
		if name.Len() == typeoffset-off {
			name.Reset()
			continue
		}

		// create space in the message to receive the expanded name.
		expand := name.Len() - (typeoffset - off)
		println("NEED more bytes", expand, typeoffset-off, name.Len())
		m.octets = append(m.octets[:off], append(make([]byte, expand), m.octets[off:]...)...)

		copy(m.octets[off:], name.Bytes())
		name.Reset()
	}
}

// compressibleType is a map of RR types that have compressible rdata.
var compressibleType = map[dnswire.Type]struct{}{
	TypeMX: {},
}

// compress ...
func compress() {}

// decompress decompresses the name starting at off. The bytes.Buffer will be written with the expanded name.
func decompress(octets []byte, off int, name *bytes.Buffer) bool {
	ptr := 0
Loop:
	for {
		if off > len(octets)-1 {
			return false
		}
		c := int(octets[off])
		off++
		switch c & 0xC0 {
		case 0x00:
			if c == 0x00 { // end of the name
				name.WriteByte(0)
				break Loop
			}
			name.Write(octets[off-1 : off+c])
			off += c
		case 0xC0:
			if ptr++; ptr > maxPointers {
				return false
			}
			c1 := int(octets[off]) // the next octet
			off = ((c^0xC0)<<8 | c1)
		default:
			return false
		}
	}
	return true
}
