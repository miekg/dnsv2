package dns

// In this file we define all the EDNS0 Options we can handle, "go generate" will generate some methods for us.
// See types.go for the supported struct tags.

import (
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"strings"
)

type (
	// An Option represents an OPT RR rdata value. Basic usage for adding an option to an OPT RR:
	//
	//	opt := &OPT{Header: Header{Name: NewName(".")}}
	//	nsid := &NSID{ID: []byte("AA")}
	//	opt.Options = []Option{nsid}
	//
	Option interface {
		// Len returns the option's value length. This is excluding the option code and length (which is always
		// 4 octets): len(o.Data()) = o.Len() + 4.
		Len() int

		// Data returns the option's values. The buffer returned is in wire format, all options require option
		// code and length, this is prepended in the buffer.
		Data() []byte

		// String returns the string representation of the EDNS0 option.
		String() string

		// Write writes the rdata encoded in buf into the EDNS0 option.
		Write(buf []byte) error
	}

	// Code represents the 2 byte option code.
	Code [2]byte
)

// Supported EDNS0 Option Codes.
var (
	CodeNone   = Code{0, 0}
	CodeNSID   = Code{0, 3}
	CodeCookie = Code{0, 10}
)

/*
OPT is the EDNS0 RR appended to messages to convey extra (meta) information. See RFC 6891. Each option is encoded as:

	            +0 (MSB)                            +1 (LSB)
	   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
	0: |                          OPTION-CODE                          |
	   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
	2: |                         OPTION-LENGTH                         |
	   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
	4: |                                                               |
	   /                          OPTION-DATA                          /
	   /                                                               /
	   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
*/
type OPT struct {
	Header
	Options []Option `dns:"len,-data,-string"`
}

func (rr *OPT) Data(i int) []byte {
	if i < 0 || i >= rr.Len() {
		return nil
	}
	return rr.Options[i].Data()
}
func (rr *OPT) String() string {
	b := &strings.Builder{}
	// don't write the type here.
	b.WriteString("\t")
	for i := 0; i < rr.Len(); i++ {
		b.WriteString(rr.Options[i].String())
	}
	return b.String()
}

func (rr *OPT) Write(msg []byte, offset, n int) error {
	i := 0
	// check n
	for i < len(msg[offset:]) {
		code := Code{msg[offset+i], msg[offset+i+1]}
		optfunc, ok := codeToOption[code]
		if !ok {
			optfunc = func() Option { return new(UnknownEDNS0) }
		}
		i += 2
		rdl := int(binary.BigEndian.Uint16(msg[offset+i:]))
		i += 2
		// length checks
		opt := optfunc()
		err := opt.Write(msg[offset+i : offset+i+rdl])
		if err != nil {
			return err
		}
		i += rdl
		rr.Options = append(rr.Options, opt)
	}
	return nil
}

// ExtendedRcode returns the extended Rcode.
func (rr *OPT) ExtendedRcode() uint8 { return rr.Hdr().TTL[0] }

func (rr *OPT) Version() uint8 { return rr.Hdr().TTL[1] }

func (rr *OPT) Do() bool { return false }

func (rr *OPT) Size() uint16 { return binary.BigEndian.Uint16(rr.Hdr().Class[:]) }

// optionHeader return the code and length as bytes of the EDNS0 Option code.
func optionHeader(e Option) [4]byte {
	code := OptionCode(e)
	return [4]byte{code[0], code[1], byte(e.Len() >> 8), byte(e.Len())}
}

// UnknownEDNS0 is an unknown EDNS0 Option. Similar in style to RFC 3597 handling.
type UnknownEDNS0 struct {
	Code           // Code holds the option code number of the unknown option code we're holding.
	Unknown []byte // Data as-is.
}

func (o *UnknownEDNS0) Len() int { return len(o.Unknown) }

func (o *UnknownEDNS0) String() string {
	c := binary.BigEndian.Uint16(o.Code[:])
	l := hex.EncodedLen(len(o.Unknown))
	return "CODE" + strconv.FormatUint(uint64(c), 10) + "\t\\# " + strconv.FormatUint(uint64(l), 10) + " " + hex.EncodeToString(o.Unknown)
}

func (o *UnknownEDNS0) Data() []byte {
	header := optionHeader(o)
	return append(header[:], o.Unknown...)
}
func (o *UnknownEDNS0) Write(buf []byte) error { o.Unknown = buf; return nil }

// NSID Option.
type NSID struct {
	ID []byte // ID is a hex encoded string.
}

func (o *NSID) Len() int       { return len(o.ID) }
func (o *NSID) String() string { return "NSID: " + hex.EncodeToString(o.ID) }
func (o *NSID) Data() []byte {
	header := optionHeader(o)
	return append(header[:], o.ID...)
}
func (o *NSID) Write(buf []byte) error { o.ID = buf; return nil }

// Cookie Option.
type COOKIE struct {
	Cookie []byte // Cookie is a hex encoded string.
}

func (o *COOKIE) Len() int       { return len(o.Cookie) }
func (o *COOKIE) String() string { return "COOKIE: " + hex.EncodeToString(o.Cookie) }

func (o *COOKIE) Data() []byte {
	header := optionHeader(o)
	return append(header[:], o.Cookie...)
}
func (o *COOKIE) Write(buf []byte) error { o.Cookie = buf; return nil }
