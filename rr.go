package dns

import (
	"bytes"
	"encoding/binary"
	"strconv"
	"strings"

	"github.com/miekg/dnsv2/dnswire"
)

// RFC3597 represents an unknown/generic RR. See RFC 3597.
type RFC3597 struct {
	Header
	octets []byte `dns:"Data:Hex"`
}

// A RR. See RFC 1035.
type A struct {
	Header
	octets []byte `dns:"A:IPv4"`
}

// MX RR, See RFC 1035.
type MX struct {
	Header
	octets []byte `dns:"Preference:Uint16,Mx:Name"`
}

// OPT is the EDNS0 RR appended to messages to convey extra (meta) information. See RFC 6891.
type OPT struct {
	Header
	octets []byte `dns:"Option:[]byte"`
}

var (
	_ RR = &MX{}
	_ RR = &A{}
	_ RR = &RFC3597{}
)

func _Type(rr RR, x ...dnswire.Type) (dnswire.Type, error) {
	off := dnswire.JumpName(rr.Octets(), 0)
	if off == 0 {
		return 0, ErrBufName
	}
	if off+2 < len(rr.Octets()) {
		return TypeNone, &Error{err: "overflow reading RR type"}
	}
	if len(x) == 0 {
		i := binary.BigEndian.Uint16(rr.Octets()[off:])
		return dnswire.Type(i), nil
	}
	binary.BigEndian.PutUint16(rr.Octets()[off:], uint16(x[0]))
	return TypeNone, nil
}

func _Class(rr RR, x ...dnswire.Class) (dnswire.Class, error) {
	off := dnswire.JumpName(rr.Octets(), 0)
	if off == 0 {
		return 0, ErrBufName
	}
	if off+4 > len(rr.Octets()) {
		return ClassNone, &Error{err: "overflow reading RR class"}
	}
	if len(x) == 0 {
		i := binary.BigEndian.Uint16(rr.Octets()[off+2:])
		return dnswire.Class(i), nil
	}
	binary.BigEndian.PutUint16(rr.Octets()[off+2:], uint16(x[0]))
	return ClassNone, nil
}

func _TTL(rr RR, x ...dnswire.TTL) (dnswire.TTL, error) {
	off := dnswire.JumpName(rr.Octets(), 0)
	if off == 0 {
		return 0, ErrBufName
	}
	if off+8 > len(rr.Octets()) {
		return dnswire.TTL(0), &Error{err: "overflow reading RR ttl"}
	}
	if len(x) == 0 {
		i := binary.BigEndian.Uint32(rr.Octets()[off+4:])
		return dnswire.TTL(i), nil
	}
	binary.BigEndian.PutUint32(rr.Octets()[off+4:], uint32(x[0]))
	return dnswire.TTL(0), nil
}

func _Len(rr RR, x ...uint16) (uint16, error) {
	off := dnswire.JumpName(rr.Octets(), 0)
	if off == 0 {
		return 0, ErrBufName
	}
	if off+10 > len(rr.Octets()) {
		return 0, &Error{err: "overflow reading RR rdlength"}
	}
	if len(x) == 0 {
		i := binary.BigEndian.Uint16(rr.Octets()[off+8:])
		if off+int(i) > len(rr.Octets()) {
			return 0, &Error{err: "bad rdlength"}
		}
		return i, nil
	}
	binary.BigEndian.PutUint16(rr.Octets()[off+8:], x[0])
	return 0, nil
}

func _Name(rr RR, x ...dnswire.Name) (dnswire.Name, error) {
	if len(x) != 0 {
		// allocate room for the name and type, class, ttl and length
		needed := len(x[0]) + 2 + 2 + 2 + 4
		if l := len(rr.Octets()); l < needed {
			extra := make([]byte, needed-l)
			buf := append(rr.Octets(), extra...)
			copy(buf[0:], x[0])
			rr.Octets(buf)
		}
		return nil, nil
	}
	name := bytes.NewBuffer(make([]byte, 0, 32)) // [bytes.Buffer] uses a 64 byte buffer, most names aren't that long, cut this in half.
	off := 0
	ptr := 0
	for {
		c := int(rr.Octets()[off])
		name.WriteByte(rr.Octets()[off])

		switch c & 0xC0 {
		case 0x00:
			println(off, "C", c, "masked", c&0xc0)
			if c == 0x00 { // end of the name
				name.WriteByte(0)
				return dnswire.Name(name.Bytes()), nil
			}

			name.Write(rr.Octets()[off : off+c])
			off += c

		case 0xC0:
			if ptr++; ptr > 10 { // Every label can be a pointer, so the max is maxlabels.
				return nil, &Error{err: "too many compression pointers"}
			}
			c1 := int(rr.Octets()[off+1]) // the next octet
			off = ((c^0xC0)<<8 | c1)
			println("pointer", off)

		default:
			// 0x80 and 0x40 are reserved
			return nil, ErrLabelType
		}
	}
}

func _String(rr RR) string {
	s := strings.Builder{}
	name, _ := rr.Name()
	s.WriteString(name.String())
	s.WriteByte('\t')
	ttl, _ := rr.TTL()
	s.WriteString(strconv.FormatInt(int64(ttl), 10))
	s.WriteByte('\t')
	class, _ := rr.Class()
	s.WriteString(ClassToString[class])
	s.WriteByte('\t')
	typ, _ := rr.Type() // If known type, use that!
	s.WriteString(TypeToString[typ])
	return s.String()
	// return fmt.Sprintf("%v", rr.Octets())
}
