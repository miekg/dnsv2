package dns

import (
	"encoding/binary"

	"github.com/miekg/dnsv2/dnswire"
)

const (
	ClassNone = dnswire.Class(0) // ClassNone signals a class not found condition.
	// Valid classes in DNS, usually only ClassINET is used.
	ClassINET   = dnswire.Class(1)
	ClassCSNET  = dnswire.Class(2)
	ClassCHAOS  = dnswire.Class(3)
	ClassHESIOD = dnswire.Class(4)
	ClassNONE   = dnswire.Class(254)
	ClassANY    = dnswire.Class(255)
)

const (
	TypeNone = dnswire.Type(0) // TypeNone signals a type not found condition.
	// Valid DNS RR types.
	TypeMX = dnswire.Type(15)
)

// Header is the header of an RR. All DNS resource records share this.
type Header interface {
	// If Type does not have a parameter it returns the RR's type. If a parameter is given it sets the RR's type.
	Type(x ...dnswire.Type) dnswire.Type
	// If TTL does not have a parameter it returns the RR's TTL. If a parameter is given it sets the RR's TTL.
	TTL(x ...dnswire.TTL) dnswire.TTL
	// If Class does not have a parameter it returns the RR's class. If a parameter is given it sets the RR's class.
	Class(x ...dnswire.Class) dnswire.Class
	// If Name does not have a parameter it returns the RR's owner name. If a parameter is given it sets the
	// RR's owner name. Not that the name should not be compressed.
	Name(x ...dnswire.Name) (dnswire.Name, error)
}

// header implements Header.
type header struct {
	octets []byte
}

func (h header) Type(x ...dnswire.Type) (dnswire.Type, error) {
	name, err := h.Name()
	if err != nil {
		return TypeNone, err
	}
	if len(name)+2 < len(h.octets) {
		return TypeNone, &Error{err: "overflow reading RR type"}
	}
	i := binary.BigEndian.Uint16(h.octets[len(name):])
	return dnswire.Type(i), nil
}

func (h header) Class(x ...dnswire.Class) (dnswire.Class, error) {
	name, err := h.Name()
	if err != nil {
		return ClassNone, err
	}
	if len(name)+4 < len(h.octets) {
		return ClassNone, &Error{err: "overflow reading RR class"}
	}
	i := binary.BigEndian.Uint16(h.octets[len(name)+2:])
	return dnswire.Class(i), nil
}

func (h header) TTL(x ...dnswire.TTL) (dnswire.TTL, error) {
	name, err := h.Name()
	if err != nil {
		return dnswire.TTL(0), err
	}
	if len(name)+8 < len(h.octets) {
		return dnswire.TTL(0), &Error{err: "overflow reading RR ttl"}
	}
	i := binary.BigEndian.Uint32(h.octets[len(name)+4:])
	return dnswire.TTL(i), nil
}

func (h header) Name(x ...dnswire.Name) (dnswire.Name, error) {
	off := 0
	for {
		c := int(h.octets[off])
		off++
		switch c & 0xC0 {
		case 0x00:
			if c == 0x00 {
				// end of the name
				return dnswire.Name(h.octets[:off]), nil
			}
			off += c
		case 0xC0:
			// Pointer to somewhere else in msg. We can't deal with that here because we don't have the message.
			// Return error here.
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

// An RR represents a resource record.
type RR interface {
	Header
	// If Octets does not have a parameter it returns the wire encoding octets for this RR. If a parameter is
	// given the octect are written to the RR.
	Octets(x ...[]byte) []byte
}

// Msg contains the layout of a DNS message. A DNS message has 4 sections, the question, answer, authority and additional section.
// In this library _another_ section is added the pseudo section; this section contains EDNS0 "records" and a possible TSIG record.
type Msg struct {
	octets []byte
}

// Section is a section in a DNS message.
type Section struct {
	msg *Msg // msg is a pointer back the message this section belong in. This is needed to resolve compression pointers.
	rrs []RR
}
