package dns

import "github.com/miekg/dnsv2/dnswire"

const (
	// Valid classes in DNS, usually only ClassINET is used.
	ClassINET   = dnswire.Class(1)
	ClassCSNET  = dnswire.Class(2)
	ClassCHAOS  = dnswire.Class(3)
	ClassHESIOD = dnswire.Class(4)
	ClassNONE   = dnswire.Class(254)
	ClassANY    = dnswire.Class(255)
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
	Name(x ...dnswire.Name) dnswire.Name
}

// An RR represents a resource record.
type RR interface {
	Header
	// If Octets does not have a parameter it returns the wire encoding octets for this RR. If a parameter is
	// given the octect are written to the RR.
	Octets(x ...[]byte) []byte
}
