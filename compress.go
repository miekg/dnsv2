package dns

import (
	"bytes"
	"encoding/binary"

	"github.com/miekg/dnsv2/dnswire"
)

// Compress performs DNS name compression on the entire message. After this you should not add more RRs to
// the message because this messes up the compression pointers (unless you add at the end, either the
// Additional or Pseudo section).
func (m *Msg) Compress() {
	// todo
}

// Decompress resolves all compression pointers in the message.
func (m *Msg) Decompress() error {
	// We walk the entire message and track where each RR begins. Then we walk this list backwards and resolve
	// each compression pointer and replace those bytes with the expanded name.
	//
	// For RRs that can have compressed rdata we basically do the same, but then we also need to adjust the
	// rdlength uint16 in the message to adjust for the new size.

	offsets := make([]int, 0, 7) // 7: conservative guess on how many RR we expect in the common case.
	j := dnswire.JumpName(m.octets, MsgHeaderLen)
	if j == 0 {
		return ErrBuf
	}
	offsets = append(offsets, j+4) // question name + type (2) + class (2)
	i := 0                         // start of the RR after the question section.
	for {
		j = dnswire.Jump(m.octets, offsets[i])
		if j == 0 {
			break
		}
		offsets = append(offsets, j)
		i++
	}

	name := bytes.NewBuffer(make([]byte, 0, 32)) // [bytes.Buffer] uses a 64 byte buffer, most RRs aren't that long, cut this in half.

	for i := len(offsets) - 1; i >= 0; i-- {
		off := offsets[i]

		// rrtype is offset + Name + 0
		typeoffset := dnswire.JumpName(m.octets, off)
		rrtype := dnswire.Type(binary.BigEndian.Uint16(m.octets[typeoffset:]))
		rdlenoffset := typeoffset + 8
		rdlen := binary.BigEndian.Uint16(m.octets[rdlenoffset:])

		// if the new name is longer, we have something expanded, otherwise continue
		if err := decompress(m.octets, off, name); err != nil {
			return err
		}
		if name.Len() == typeoffset-off {
			name.Reset()
			continue
		}

		// create space in the message to receive the expanded name.
		expand := name.Len() - (typeoffset - off)
		m.octets = dnswire.Extend(m.octets, off, expand)

		copy(m.octets[off:], name.Bytes())
		name.Reset()

		/*
			// compressed rdata for a few types defined in RFC 1035: NS, CNAME, SOA, PTR, MX, and some obsoleted
			// ones: MR, MF etc.
			//
			// The original offset hasn't changed and we added expand octets, so the start of the rdata of the RR
			// is now: typeoffset + expand + 2 (type) + 2 (class) + 4 (ttl) + 2 (rdlength)
			off = typeoffset + expand + 2 + 2 + 4 + 2 // rdlenoffset is this -2 (to set the adjusted new size)

			switch rrtype {
			case TypeMX:
				mxoff := off + 2 // 2 for prio (uint16)
				if err := decompress(m.octets, mxoff, name); err != nil {
					return err
				}
				if name.Len()+2 > int(rdlen) {
					println("COMPRESSED RDATA")
				}
			}
		*/

		rdlen = rdlen
		rrtype = rrtype
	}
	return nil
}

// compress ...
func compress() {}

// decompress decompresses the name starting at off. The bytes.Buffer will be written with the expanded name.
func decompress(octets []byte, off int, name *bytes.Buffer) error {
	ptr := 0
Loop:
	for {
		if off > len(octets)-1 {
			return ErrBuf
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
			if ptr++; ptr > maxPtrs {
				return ErrPtr
			}
			c1 := int(octets[off]) // the next octet
			off = ((c^0xC0)<<8 | c1)
		default:
			return ErrLabelType
		}
	}
	return nil
}
