package dns

import (
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
	Type(x ...dnswire.Type) (dnswire.Type, error)
	// If TTL does not have a parameter it returns the RR's TTL. If a parameter is given it sets the RR's TTL.
	TTL(x ...dnswire.TTL) (dnswire.TTL, error)
	// If Class does not have a parameter it returns the RR's class. If a parameter is given it sets the RR's class.
	Class(x ...dnswire.Class) (dnswire.Class, error)
	// If Name does not have a parameter it returns the RR's owner name. If a parameter is given it sets the
	// RR's owner name. Not that the name should not be compressed.
	Name(x ...dnswire.Name) (dnswire.Name, error)
	// If Len does not have a parameter it returns the RR's rdata length. If a parameter is given is sets the length.
	Len(x ...uint16) (uint16, error)
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
	ps     uint16 // pseudo section counter
}

// Section is a section in a DNS message.
type Section struct {
	msg    *Msg   // msg is a pointer back the message this section belong in. This is needed to resolve compression pointers, when returning the RRs.
	octets []byte // Contents of the section with possible compression pointers in the dns names.
}
