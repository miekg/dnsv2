package dns

import (
	"encoding/hex"
	"strconv"
)

const (
	// DefaultMsgSize is the standard default for messages larger than 512 bytes.
	DefaultMsgSize = 4096
	// MinMsgSize is the minimal size of a DNS message.
	MinMsgSize = 512
	// MaxMsgSize is the largest possible DNS message.
	MaxMsgSize = 65535

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
}

// Field is a rdata element in a resource record.
type Field interface {
	// String returns the text representation of the field.
	String() string
}

// Header is the header in a DNS resource record.
type Header struct {
	Name string `dns:"cdomain-name"`
	// type  uint16 // Inferred from the Go type.
	Class uint16 // Class is the class of the RR, this is almost always [ClassINET], if left zero, ClassINET is assumed when sending a message.
	TTL   uint32 // TTL is the time-to-live of the RR.
	// rdlength is calculated.
}

func (h Header) String(rr RR) string {
	rrtype := RRToType(rr)
	rrstr := TypeToString[rrtype]
	return ""
}

const (
	MsgHeaderLen = 12 // MsgHeaderLen is the length of the header in the DNS message.
)

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
	Opcode             int8
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
	Question []RR // Holds the RR of the question section.
	Answer   []RR // Holds the RR(s) of the answer section.
	Ns       []RR // Holds the RR(s) of the authority section.
	Extra    []RR // Holds the RR(s) of the additional section.
	Pseudo   []RR // Holds the RR(s) of the (virtual) peusdo section.

	// Data is the data of the message that was either received from the wire or is about to be send
	// over the wire. Note that this data is a snapshot of the Msg as it was packed or unpacked.
	Data []byte
}

func (h *Header) String() string {
	var s string

	if h.Rrtype == TypeOPT {
		s = ";"
		// and maybe other things
	}

	s += sprintName(h.Name) + "\t"
	s += strconv.FormatInt(int64(h.Ttl), 10) + "\t"
	s += Class(h.Class).String() + "\t"
	s += Type(h.Rrtype).String() + "\t"
	return s
}

func (h *RR_Header) len(off int, compression map[string]struct{}) int {
	l := domainNameLen(h.Name, off, compression, true)
	l += 10 // rrtype(2) + class(2) + ttl(4) + rdlength(2)
	return l
}

func (h *RR_Header) pack(msg []byte, off int, compression compressionMap, compress bool) (off1 int, err error) {
	// RR_Header has no RDATA to pack.
	return off, nil
}

func (h *RR_Header) unpack(data, msgBuf []byte) error {
	panic("dns: internal error: unpack should never be called on RR_Header")
}

func (h *RR_Header) parse(c *zlexer, origin string) *ParseError {
	panic("dns: internal error: parse should never be called on RR_Header")
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
