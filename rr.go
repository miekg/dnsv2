package dns

import (
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

// unexported helper functions that implement the Header interface for each RR (see zrr.go).
// Note, they start with _ (so unpexported), because type is not an allowed identifier.

func _Type(rr RR, x ...dnswire.Type) (dnswire.Type, error) {
	off := dnswire.JumpName(rr.Octets(), 0)
	if off == 0 {
		return 0, ErrBufName
	}
	if off+2 > len(rr.Octets()) {
		return TypeNone, &Error{err: "overflow reading RR type"}
	}
	if len(x) == 0 {
		i := binary.BigEndian.Uint16(rr.Octets()[off:])
		if i == 0 { // infer from type (should we then also set it??)
		}
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
			copy(buf[0:], x[0]) // no copy here I think
			rr.Octets(buf)
		}
		return nil, nil
	}
	off := dnswire.JumpName(rr.Octets(), 0)
	if off == 0 {
		return nil, ErrBufName
	}
	return dnswire.Name(rr.Octets()[0:off]), nil
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
	typ, _ := rr.Type()
	s.WriteString(TypeToString[typ])
	return s.String()
	// return fmt.Sprintf("%v", rr.Octets())
}
