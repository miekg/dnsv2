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
	// Valid DNS RR types. Not that *most* of the time the RR type will be derived from the Go struct type.
	TypeA    = dnswire.Type(1)
	TypeNS   = dnswire.Type(2)
	TypeAAAA = dnswire.Type(28)
	TypeMX   = dnswire.Type(15)
	TypeSOA  = dnswire.Type(16)
	TypeOPT  = dnswire.Type(41)
)

const (
	// Valid EDNS "RR" option type codes.
	CodeNSID    = dnswire.Type(0x3) // nsid (See RFC 5001)
	CodePADDING = dnswire.Type(0xc) // padding (See RFC 7830)
)

const (
	// Message opcodes. There is no 3.
	OpcodeQuery  = dnswire.Opcode(0)
	OpcodeIQuery = dnswire.Opcode(1)
	OpcodeStatus = dnswire.Opcode(2)
	OpcodeNotify = dnswire.Opcode(4)
	OpcodeUpdate = dnswire.Opcode(5)
)

// Header is the header of an RR. All DNS resource records share this. The length of the header in an RR can
// be calculated by taking the length of the RR's Octets() and subtracting Len(). The different length are
// visialized like so:
//
//	 Name | Type | Class | TTL | rdlength | rdata
//	|_____________________________________|__________...
//	              Len()                     DataLen()
//	|________________________________________________...
//	                   len(rr.Octets())
type Header interface {
	// If Type does not have a parameter it returns the RR's type. If a parameter is given it sets the RR's type.
	// Note that Type is usualy superfluous as the RR's type is implicitly enccoded in the Go type of the struct.
	// If the found type is zero the type of the struct is returned - if the RR type is known.
	Type(x ...dnswire.Type) (dnswire.Type, error)
	// If TTL does not have a parameter it returns the RR's TTL. If a parameter is given it sets the RR's TTL.
	TTL(x ...dnswire.TTL) (dnswire.TTL, error)
	// If Class does not have a parameter it returns the RR's class. If a parameter is given it sets the RR's class.
	Class(x ...dnswire.Class) (dnswire.Class, error)
	// If Name does not have a parameter it returns the RR's owner name. If a parameter is given it sets the
	// RR's owner name. This is the only method that allocates a buffer in the RR with enough space the entire
	// header. Subsequent methods only extend this.
	Name(x ...dnswire.Name) (dnswire.Name, error)
	// If DataLen does not have a parameter it returns the RR's rdata length. If a parameter is given is sets the length.
	// An error is returned when the octets that contain this length are not there, or the length exceeds the
	// number of octets in the RR.
	DataLen(x ...uint16) (uint16, error)
	// String returns the string representation of the RR's header.
	String() string
	// Len returns the length of the header, that is the length of the name, plus type, class, ttl (4 octets)
	// and the rdlength (2). Note that only the existence of the name is checked.
	Len() int
}

const (
	MsgHeaderLen = 12 // MsgHeaderLen is the length of the header in the DNS message.
	maxPtrs      = 10 // maxPointers is the maximum number of pointers we will follow when decompressing a DNS name.
)

// An RR represents a resource record. When defining a RR struct tags are used to generate the data accessor
// functions. An example from the MX record being:
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
//
// When building an RR the name of it should be set first as this allocates enough space for the rest of the
// header. Other RR methods will error or silently fail if this is not properly allocated.
type RR interface {
	Header
	// If Octets does not have a parameter it returns the wire encoding octets for this RR. If a parameter is
	// given the octets are written to the RR.
	Octets(x ...[]byte) []byte
}

// EDNS0 determines if the "RR" is posing as an EDNS0 option. EDNS0 options are considered just RRs and must
// be added to the [Pseudo] section of a DNS message.
type EDNS0 interface {
	Pseudo() bool
}

// Msg contains the layout of a DNS message. A DNS message has 4 sections, the [Question], [Answer], [Ns]
// (authority) and [Extra] (additional) section.
// In this library _another_ section is added the [Pseudo ]section; this section contains EDNS0 "records" and a possible TSIG record.
type Msg struct {
	octets []byte
	ps     uint16 // pseudo section counter, returns EDNS0 RRs in OPT + TSIG
}

// Section is a section in a DNS message.
type Section struct {
	*Msg // Msg is a pointer back the message this section belong in.
	// Offsets into Msg where this section begins and ends, buf[start:end] are the octets this section occupies.
	start int
	end   int
}

// Valid DNS sections. A section always belong to a Msg. Note the Pseudo section is non-existent on the wire. It is purely for convenience for
// accessing EDNS0 meta records, those masquerade as RRs.
type (
	// Question holds the question section. RRs can be added just like any other sections.
	Question struct{ Section }
	// Answer holds the answer section.
	Answer struct{ Section }
	// Ns holds the authority section.
	Ns struct{ Section }
	// Extra holds the additional section. [OPT] (EDNS0) and [TISG] RRs are placed in the [Pseudo] section, not here.
	Extra struct{ Section }
	// Pseudo is a non-on-the-wire section that holds [OPT] and [TSIG] rrs. [OPT] is treated in such a way
	// that this section also seems to hold RRs of the [EDNS0] variety.
	Pseudo struct{ Section }
)

// ClassToString is a maps Classes to strings for each class wire type.
var ClassToString = map[dnswire.Class]string{
	ClassINET:   "IN",
	ClassCSNET:  "CS",
	ClassCHAOS:  "CH",
	ClassHESIOD: "HS",
	ClassNONE:   "NONE",
	ClassANY:    "ANY",
}

// OpcodeToString maps Opcodes to strings.
var OpcodeToString = map[dnswire.Opcode]string{
	OpcodeQuery:  "QUERY",
	OpcodeIQuery: "IQUERY",
	OpcodeStatus: "STATUS",
	OpcodeNotify: "NOTIFY",
	OpcodeUpdate: "UPDATE",
}
