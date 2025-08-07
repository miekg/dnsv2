package dns

import (
	"encoding/hex"
	"strconv"
	"strings"
)

//go:generate go run rr_generate.go
//go:generate go run msg_generate.go
//go:generate go run duplicate_generate.go

const (
	// DefaultMsgSize is the standard default for messages larger than 512 bytes.
	DefaultMsgSize = 4096
	// MinMsgSize is the minimal size of a DNS message.
	MinMsgSize = 512
	// MaxMsgSize is the largest possible DNS message.
	MaxMsgSize = 65535
	// MsgHeaderLen is the length of the header in the DNS message.
	MsgHeaderSize = 12

	year68     = 1 << 31 // For RFC1982 (Serial Arithmetic) calculations in 32 bits.
	defaultTtl = 3600    // Default internal TTL.
)

// An RR represents a DNS resource record.
type RR interface {
	// Header returns the header of an resource record. The header contains everything up to the rdata.
	Header() *Header
	// String returns the text representation of the resource record.
	String() string
	// Data returns all the rdata fields of the resource record.
	Data() []Field
	// Len is the length if the RR when encoded in wire format, this is not a perfect metric and returning
	// a slightly too large value is OK.
	Len() int
	// Packer
}

// If an RR implements the Typer interface it will be used to return the type of RR in the RRToType function.
// This is only needed for RRs that are defined outside of this package.
type Typer interface {
	Type() uint16
}

// Field is a rdata element in a resource record. The string representation can be configured in various ways:
//   - If a Field implements the Stringer interface it will be used to return the string presentation
//   - Otherwise if the field is a basic Go type, it will be converted to a string will be used.
type Field any

// The Packer interface defines the Pack and Unpack methods that are used to convert RRs to and from wire format.
type Packer interface {
	// Pack packs the RR into msg at offset off. Compress is used for compression, see examples in zpack.go.
	// The returned int is the new offset in msg when this RR is packed.
	Pack(msg []byte, off int, compress map[string]uint16) (int, error)
	// Unpack unpacks the RR. Data is the byte slice that should contain the all the data for the RR, msg is
	// the byte slice with the entire message; this is only used to resolve compression pointers and the new
	// RRs that can contain those (only those defined in RFC 1035).
	Unpack(data, msg []byte) error
}

// Header is the header in a DNS resource record.
type Header struct {
	Name string `dns:"cdomain-name"`
	// type is inferred from the Go type.
	Class uint16 // Class is the class of the RR, this is almost always [ClassINET], if left zero, ClassINET is assumed when sending a message.
	TTL   uint32 // TTL is the time-to-live of the RR.
	// rdlength has no use
}

// String returns the string representation of h.
func (h *Header) String(rr RR) string {
	sb := strings.Builder{}
	sb.WriteString(sprintName(h.Name))
	sb.WriteByte('\t')

	sb.WriteString(strconv.FormatInt(int64(h.TTL), 10))
	sb.WriteByte('\t')

	sb.WriteString(sprintClass(h.Class))
	sb.WriteByte('\t')

	rrtype := RRToType(rr)
	sb.WriteString(sprintClass(rrtype))
	return sb.String()
}

func (h *Header) Len() int { return len(h.Name) + 10 }

// EDNS0 determines if the "RR" is posing as an EDNS0 option. EDNS0 options are considered just RRs and must
// be added to the [Pseudo] section of a DNS message.
type EDNS0 interface {
	RR
	Pseudo() bool
}

// MsgHeader is the header of a DNS message. This contains most header bits, except Rcode as that needs to be
// set via a function because of the extended Rcode that lives in the pseudo section.
type MsgHeader struct {
	ID                 uint16
	Response           bool
	Opcode             uint8
	Authoritative      bool
	Truncated          bool
	RecursionDesired   bool
	RecursionAvailable bool
	Zero               bool
	AuthenticatedData  bool
	CheckingDisabled   bool

	rcode uint16 // 12 bits are defined, some live in the OPT RR.
}

// Msg is a DNS message.
type Msg struct {
	MsgHeader
	// Question holds a single "RR", in quotes because it is only the domain name, type and class that is
	// actually encoded here. This package takes care of taking and returning the right bit of an RR.
	// Setting the question is done like so: msg.Question = []RR{&MX{Hdr: Header{Name: "miek.nl.", Class: ClassINET}}}
	// This sets it to "miek.nl.", TypeMX, ClassINET.
	Question []RR
	Answer   []RR // Holds the RR(s) of the answer section.
	Ns       []RR // Holds the RR(s) of the authority section.
	Extra    []RR // Holds the RR(s) of the additional section, execpt records that go into the pseudo section.
	// The Pseudo section is a virtual (doesn't exist on the wire) section in this package. It holds the OPT
	// EDNS0 option codes, that are interpreted as RRs. If a TSIG record is present it also sits in this
	// section.
	Pseudo []RR // Holds the RR(s) of the (virtual) peusdo section.

	// Data is the data of the message that was either received from the wire or is about to be send
	// over the wire. Note that this data is a snapshot of the Msg as it was packed or unpacked.
	Data []byte

	Options Option // Option is a bit mask of options that control the unpacking. When zero the entire message is unpacked.
}

// Option is an option on how to handle a message. Options can be combined.
type Option uint16

const (
	OptionUnpackNone     Option = 1 << iota // Do not unpack anything, dump the message in Data and call it a day.
	OptionUnpackHeader                      // Unpack only the header of the message.
	OptionUnpackQuestion                    // Unpack only the question section of the message
)

func (h *MsgHeader) SetRcode(code uint16) {}
func (h *MsgHeader) Rcode() uint16        { return h.rcode }

// Convert a MsgHeader to a string, with dig-like headers:
//
// ;; opcode: QUERY, status: NOERROR, id: 48404
//
// ;; flags: qr aa rd ra;
func (h *MsgHeader) String() string {
	sb := strings.Builder{}
	sb.WriteString(";; opcode: ")
	sb.WriteString(OpcodeToString[h.Opcode])
	sb.WriteString(", status: ")
	sb.WriteString(RcodeToString[h.Rcode()])
	sb.WriteString(", id: ")
	sb.WriteString(strconv.Itoa(int(h.ID)))
	sb.WriteByte('\n')

	sb.WriteString(";; flags:")
	if h.Response {
		sb.WriteString(" qr")
	}
	if h.Authoritative {
		sb.WriteString(" aa")
	}
	if h.Truncated {
		sb.WriteString(" tc")
	}
	if h.RecursionDesired {
		sb.WriteString(" rd")
	}
	if h.RecursionAvailable {
		sb.WriteString(" ra")
	}
	if h.Zero {
		sb.WriteString(" z")
	}
	if h.AuthenticatedData {
		sb.WriteString(" ad")
	}
	if h.CheckingDisabled {
		sb.WriteString(" cd")
	}

	sb.WriteString(";")
	return sb.String()
}

// ToRFC3597 converts a known RR to the unknown RR representation from RFC 3597.
func (rr *RFC3597) ToRFC3597(r RR) error {
	buf := make([]byte, Len(r))
	headerEnd, off, err := packRR(r, buf, 0, compressionMap{}, false)
	if err != nil {
		return err
	}
	buf = buf[:off]

	*rr = RFC3597{Hdr: *r.Header()}
	rr.Hdr.Rdlength = uint16(off - headerEnd)

	if rr.Hdr.Rdlength == 0 {
		return nil
	}

	return rr.unpack(buf[headerEnd:], buf)
}

// fromRFC3597 converts an unknown RR representation from RFC 3597 to the known RR type.
func (rr *RFC3597) fromRFC3597(r RR) error {
	hdr := r.Header()
	*hdr = rr.Hdr

	// Can't overflow uint16 as the length of Rdata is validated in (*RFC3597).parse.
	// We can only get here when rr was constructed with that method.
	hdr.Rdlength = uint16(hex.DecodedLen(len(rr.Rdata)))

	if hdr.Rdlength == 0 {
		// Dynamic update.
		return nil
	}

	// rr.pack requires an extra allocation and a copy so we just decode Rdata
	// manually, it's simpler anyway.
	msg, err := hex.DecodeString(rr.Rdata)
	if err != nil {
		return err
	}

	return r.unpack(msg, msg)
}
