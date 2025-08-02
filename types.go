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
	TypeA   = dnswire.Type(1)
	TypeMX  = dnswire.Type(15)
	TypeOPT = dnswire.Type(41)
)

const (
	// Valid EDNS "RR" option type codes.
	CodeNSID    = dnswire.Type(0x3) // nsid (See RFC 5001)
	CodePADDING = dnswire.Type(0xc) // EDNS0 padding (See RFC 7830)
)

// Header is the header of an RR. All DNS resource records share this.
type Header interface {
	// If Type does not have a parameter it returns the RR's type. If a parameter is given it sets the RR's type.
	// Note that Type is usualy superfluous as the RR's type is implicitly enccoded in the Go type of the struct.
	Type(x ...dnswire.Type) (dnswire.Type, error)
	// If TTL does not have a parameter it returns the RR's TTL. If a parameter is given it sets the RR's TTL.
	TTL(x ...dnswire.TTL) (dnswire.TTL, error)
	// If Class does not have a parameter it returns the RR's class. If a parameter is given it sets the RR's class.
	Class(x ...dnswire.Class) (dnswire.Class, error)
	// If Name does not have a parameter it returns the RR's owner name. If a parameter is given it sets the
	// RR's owner name. Not that the name can be compressed.
	Name(x ...dnswire.Name) (dnswire.Name, error)
	// If Len does not have a parameter it returns the RR's rdata length. If a parameter is given is sets the length.
	Len(x ...uint16) (uint16, error)
}

// An RR represents a resource record. When defining a RR struct tags are used to generate the Rdata accessor functions and example
// from the MX record being:
//
//	octets []byte `dns:"Preference:Uint16,Mx:Name"`
//
// This defines the rdata as being a []byte (as is custom) and the defines 2 rdata fields:
//   - Preference, a dnswire.Uint16, and
//   - Mx, a dnswire.Name
//
// This generates two methods on *[MX]:
//   - Preference(x ...dnswire.Uint16) dnswire.Uint16, and
//   - Mx(x ...dnswire.Name) dnswire.Name
//
// That allows for setting and getting the fields' values. Note that the return types should all exist in the
// [dnswire] package, alternatively you can use native Go types.
type RR interface {
	Header
	// If Octets does not have a parameter it returns the wire encoding octets for this RR. If a parameter is
	// given the octect are written to the RR.
	Octets(x ...[]byte) []byte
	// Msg returns a pointer to the dns message this RR was read from. If a parameter is given the RR is "attached" to
	// that message. A RR does not need to be attached to a dns messsage, for instance when being parsed from
	// a file or a string. In that case this method return nil. Note that in the latter case no compression
	// pointers need to be resolved.
	Msg(x ...*Msg) *Msg
}

// EDNS0 determines if the "RR" is posing as an EDNS0 option. EDNS0 options are considered just RRs and must
// be added to the [Pseudo] section of a DNS message.
type EDNS0 interface {
	Pseudo() bool
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
	octets []byte // Contents of the section with possible compression pointers in the dns names. This data is owned by Msg.
}
