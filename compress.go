package dns

import (
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

	// We assume the question section is not compressed, consists only out of 1 question.
	for i := len(offsets) - 1; i > 0; i-- {
		offset := offsets[i]

		// rrtype is offset + Name + 0
		typeoffset := dnswire.JumpName(m.octets, offset)
		rrtype := dnswire.Type(binary.BigEndian.Uint16(m.octets[typeoffset:]))
		println("type:", rrtype.String())
		rdlengthoffset := typeoffset + 8
		rdlength := binary.BigEndian.Uint16(m.octets[rdlengthoffset:])
		println("rdlength:", rdlength)

	}
}

// compressibleType is a map of RR types that have compressible rdata.
var compressibleType = map[dnswire.Type]struct{}{
	TypeMX: {},
}
