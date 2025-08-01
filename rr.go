package dns

import (
	"bytes"
	"encoding/binary"

	"github.com/miekg/dnsv2/dnswire"
)

// A RR. See RFC 1035.
type A struct {
	Header
	msg    *Msg
	octets []byte `dns:"A:IPv4"`
}

func (rr *A) Msg(x ...*Msg) *Msg {
	if len(x) == 0 {
		return rr.msg
	}
	rr.msg = x[0]
	return nil
}

func (rr *A) Name(x ...dnswire.Name) (dnswire.Name, error) { return Hdr{rr.octets, rr.msg}.Name(x...) }
func (rr *A) Class(x ...dnswire.Class) (dnswire.Class, error) {
	return Hdr{rr.octets, rr.msg}.Class(x...)
}
func (rr *A) TTL(x ...dnswire.TTL) (dnswire.TTL, error) { return Hdr{rr.octets, rr.msg}.TTL(x...) }

func (rr *A) Octets(x ...[]byte) []byte {
	if len(x) == 0 {
		return rr.octets
	}
	rr.octets = x[0]
	return nil
}

// MX RR, See RFC 1035.
type MX struct {
	Header
	msg    *Msg
	octets []byte `dns:"Preference:Uint16,Mx:Name"`
}

var (
	_ RR = &MX{}
	_ RR = &A{}
)

func (rr *MX) Msg(x ...*Msg) *Msg {
	if len(x) == 0 {
		return rr.msg
	}
	rr.msg = x[0]
	return nil
}

func (rr *MX) Name(x ...dnswire.Name) (dnswire.Name, error) { return Hdr{rr.octets, rr.msg}.Name(x...) }
func (rr *MX) Class(x ...dnswire.Class) (dnswire.Class, error) {
	return Hdr{rr.octets, rr.msg}.Class(x...)
}
func (rr *MX) TTL(x ...dnswire.TTL) (dnswire.TTL, error) { return Hdr{rr.octets, rr.msg}.TTL(x...) }

func (rr *MX) Octets(x ...[]byte) []byte {
	if len(x) == 0 {
		return rr.octets
	}
	rr.octets = x[0]
	return nil
}

// Hdr implements Header, this is used in each RR.
type Hdr struct {
	octets []byte
	msg    *Msg
}

var _ Header = Hdr{}

func (h Hdr) Class(x ...dnswire.Class) (dnswire.Class, error) {
	name, err := h.Name()
	if err != nil {
		return ClassNone, err
	}
	if len(name)+4 > len(h.octets) {
		return ClassNone, &Error{err: "overflow reading RR class"}
	}
	i := binary.BigEndian.Uint16(h.octets[len(name)+2:])
	return dnswire.Class(i), nil
}

func (h Hdr) TTL(x ...dnswire.TTL) (dnswire.TTL, error) {
	name, err := h.Name()
	if err != nil {
		return dnswire.TTL(0), err
	}
	if len(name)+8 > len(h.octets) {
		return dnswire.TTL(0), &Error{err: "overflow reading RR ttl"}
	}
	i := binary.BigEndian.Uint32(h.octets[len(name)+4:])
	return dnswire.TTL(i), nil
}

func (h Hdr) Len(x ...uint16) (uint16, error) {
	name, err := h.Name()
	if err != nil {
		return 0, err
	}
	if len(name)+10 > len(h.octets) {
		return 0, &Error{err: "overflow reading RR rdlength"}
	}
	i := binary.BigEndian.Uint16(h.octets[len(name)+8:])
	return i, nil
}

func (h Hdr) Name(x ...dnswire.Name) (dnswire.Name, error) {
	name := bytes.Buffer{}
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
