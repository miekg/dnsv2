package dns

import (
	"encoding/binary"
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

		// Write writes the rdata encoded in msg staring at offset into the EDNS0 option.
		// The returned integer is how many octets have been written.
		Write(msg []byte, offset int) (int, error)
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
OPT is the EDNS0 RR appended to messages to convey extra (meta) information. See RFC 6891.
Each option is encoded as:

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
	Options []Option
}

// OptHdrString() // takes an rr.Header and formats it so you can have pretty printed EDNS0 OPT RR.
// OptHdr and OptHdr.String()

func (rr *OPT) Hdr() *Header { return &rr.Header }
func (rr *OPT) Len() int     { return len(rr.Options) }
func (rr *OPT) Data(i int) []byte {
	if i < 0 || i >= rr.Len() {
		return nil
	}
	return rr.Options[i].Data()
}
func (rr *OPT) String() string {
	b := &strings.Builder{}
	b.WriteString(TypeToString[TypeOPT])
	b.WriteString("\t")
	for i := 0; i < rr.Len(); i++ {
		b.WriteString(rr.Options[i].String())
	}
	return b.String()
}

func (rr *OPT) Write(msg []byte, offset int) (int, error) {
	i := 0
	for i < len(msg[offset:]) {
		code := Code{msg[i], msg[i+1]}
		optfunc, ok := codeToOption[code]
		if !ok {
			println("UNKNOWN option code", msg[i], msg[i+1])
			// now what??
		}
		i += 2
		rdl := int(binary.BigEndian.Uint16(msg[i:]))
		i += 2
		// length checks
		opt := optfunc()
		n, err := opt.Write(msg, i)
		if err != nil {
			return i, err
		}
		println("RDL", rdl, n)
		i += rdl //+1?
	}
	return i, nil
}

// OptionCode returns the option code of the Option.
func OptionCode(e Option) Code {
	switch e.(type) {
	case *NSID:
		return CodeNSID
	case *COOKIE:
		return CodeCookie
	}
	return CodeNone
}

func optionHeader(e Option) [4]byte {
	code := OptionCode(e)
	return [4]byte{code[0], code[1], byte(e.Len() >> 8), byte(e.Len())}
}

// NSID Option.
type NSID struct {
	ID []byte // ID is a hex encoded string.
}

func (o *NSID) Len() int       { return len(o.ID) }
func (o *NSID) String() string { return "NSID: " + string(o.ID) }
func (o *NSID) Data() []byte {
	header := optionHeader(o)
	return append(header[:], o.ID...)
}
func (o *NSID) Write(msg []byte, offset int) (int, error) { o.ID = msg[offset:]; return 0, nil }

//  Cookie Option.
type COOKIE struct {
	Cookie []byte // Cookie is a hex encoded string.
}

func (o *COOKIE) Len() int       { return len(o.Cookie) }
func (o *COOKIE) String() string { return "COOKIE: " + string(o.Cookie) }
func (o *COOKIE) Data() []byte {
	header := optionHeader(o)
	return append(header[:], o.Cookie...)
}
func (o *COOKIE) Write(msg []byte, offset int) (int, error) { o.Cookie = msg[offset:]; return 0, nil }

var codeToOption = map[Code]func() Option{
	CodeNSID:   func() Option { return new(NSID) },
	CodeCookie: func() Option { return new(COOKIE) },
}

var (
	_ Option = new(NSID)
	_ Option = new(COOKIE)
)
