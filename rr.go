package dns

import (
	"bytes"
	"encoding/binary"

	"github.com/miekg/dnsv2/dnswire"
)

// RFC3597 represents an unknown/generic RR. See RFC 3597.
type RFC3597 struct {
	Header
	msg    *Msg
	octets []byte `dns:"Data:Hex"`
}

// A RR. See RFC 1035.
type A struct {
	Header
	msg    *Msg
	octets []byte `dns:"A:IPv4"`
}

// MX RR, See RFC 1035.
type MX struct {
	Header
	msg    *Msg
	octets []byte `dns:"Preference:Uint16,Mx:Name"`
}

// OPT is the EDNS0 RR appended to messages to convey extra (meta) information. See RFC 6891.
type OPT struct {
	Header
	msg    *Msg
	octets []byte `dns:"Option:[]byte"`
}

var (
	_ RR = &MX{}
	_ RR = &A{}
	_ RR = &RFC3597{}
)

// Hdr implements Header, this is used in each RR.
type Hdr struct {
	octets []byte
	msg    *Msg
}

var _ Header = Hdr{}

func (h Hdr) Type(x ...dnswire.Type) (dnswire.Type, error) {
	off := dnswire.JumpName(h.octets, 0)
	if off == 0 {
		return 0, ErrBufName
	}
	if off+2 < len(h.octets) {
		return TypeNone, &Error{err: "overflow reading RR type"}
	}
	if len(x) == 0 {
		i := binary.BigEndian.Uint16(h.octets[off:])
		return dnswire.Type(i), nil
	}
	binary.BigEndian.PutUint16(h.octets[off:], uint16(x[0]))
	return TypeNone, nil
}

func (h Hdr) Class(x ...dnswire.Class) (dnswire.Class, error) {
	off := dnswire.JumpName(h.octets, 0)
	if off == 0 {
		return 0, ErrBufName
	}
	if off+4 > len(h.octets) {
		return ClassNone, &Error{err: "overflow reading RR class"}
	}
	if len(x) == 0 {
		i := binary.BigEndian.Uint16(h.octets[off+2:])
		return dnswire.Class(i), nil
	}
	binary.BigEndian.PutUint16(h.octets[off+2:], uint16(x[0]))
	return ClassNone, nil
}

func (h Hdr) TTL(x ...dnswire.TTL) (dnswire.TTL, error) {
	off := dnswire.JumpName(h.octets, 0)
	if off == 0 {
		return 0, ErrBufName
	}
	if off+8 > len(h.octets) {
		return dnswire.TTL(0), &Error{err: "overflow reading RR ttl"}
	}
	if len(x) == 0 {
		i := binary.BigEndian.Uint32(h.octets[off+4:])
		return dnswire.TTL(i), nil
	}
	binary.BigEndian.PutUint32(h.octets[off+4:], uint32(x[0]))
	return dnswire.TTL(0), nil
}

func (h Hdr) Len(x ...uint16) (uint16, error) {
	off := dnswire.JumpName(h.octets, 0)
	if off == 0 {
		return 0, ErrBufName
	}
	if off+10 > len(h.octets) {
		return 0, &Error{err: "overflow reading RR rdlength"}
	}
	if len(x) == 0 {
		i := binary.BigEndian.Uint16(h.octets[off+8:])
		if off+int(i) > len(h.octets) {
			return 0, &Error{err: "bad rdlength"}
		}
		return i, nil
	}
	binary.BigEndian.PutUint16(h.octets[off+8:], x[0])
	return 0, nil
}

func (h Hdr) Name(x ...dnswire.Name) (dnswire.Name, error) {
	if len(x) != 0 {
		// allocate room for the name and type, class, ttl and length
		needed := len(x[0]) + 2 + 2 + 2 + 4
		println("ALLOCATING")
		if len(h.octets) < needed {
			extra := make([]byte, needed-len(h.octets))
			h.octets = append(h.octets, extra...)
		}

		return nil, nil
	}
	name := bytes.NewBuffer(make([]byte, 32)) // [bytes.Buffer] uses a 64 byte buffer, most names aren't that long, cut this in half.
	off := 0
	ptr := 0
	for {
		c := int(h.octets[off])
		name.WriteByte(h.octets[off])
		off++
		switch c & 0xC0 {
		case 0x00:
			if c == 0x00 { // end of the name
				return dnswire.Name(name.Bytes()), nil
			}
			off += c
		case 0xC0:
			if h.msg == nil {
				// Pointer to somewhere else in msg. We can't deal with that here because we don't have the message.
				return nil, ErrPtr
			}
			if ptr++; ptr > 10 {
				return nil, &Error{err: "too many compression pointers"}
			}
			off = (c^0xC0)<<8 | c

		default:
			// 0x80 and 0x40 are reserved
			return nil, ErrLabelType
		}
		if off > len(h.octets) {
			return nil, ErrBuf
		}
	}
}
