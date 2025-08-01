package dns

import (
	"encoding/binary"

	"github.com/miekg/dnsv2/dnswire"
)

// MX RR, See RFC 1035.
type MX struct {
	Header
	octets []byte `dns:"Preference:Uint16,Mx:Name"`
}

var _ RR = &MX{}

func (rr *MX) Name(x ...dnswire.Name) (dnswire.Name, error)    { return Hdr{rr.octets}.Name(x...) }
func (rr *MX) Type(x ...dnswire.Type) (dnswire.Type, error)    { return Hdr{rr.octets}.Type(x...) }
func (rr *MX) Class(x ...dnswire.Class) (dnswire.Class, error) { return Hdr{rr.octets}.Class(x...) }
func (rr *MX) TTL(x ...dnswire.TTL) (dnswire.TTL, error)       { return Hdr{rr.octets}.TTL(x...) }

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
}

var _ Header = Hdr{}

func (h Hdr) Type(x ...dnswire.Type) (dnswire.Type, error) {
	// Need to set these too
	name, err := h.Name()
	if err != nil {
		return TypeNone, err
	}
	if len(name)+2 > len(h.octets) {
		return TypeNone, &Error{err: "overflow reading RR type"}
	}
	i := binary.BigEndian.Uint16(h.octets[len(name):])
	return dnswire.Type(i), nil
}

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
	off := 0
	for {
		c := int(h.octets[off])
		off++
		switch c & 0xC0 {
		case 0x00:
			if c == 0x00 { // end of the name
				return dnswire.Name(h.octets[:off]), nil
			}
			off += c
		case 0xC0:
			// Pointer to somewhere else in msg. We can't deal with that here because we don't have the message.
			return nil, ErrPointer
		default:
			// 0x80 and 0x40 are reserved
			return nil, ErrLabelType
		}
		if off > len(h.octets) {
			return nil, ErrBuf
		}
	}
}
