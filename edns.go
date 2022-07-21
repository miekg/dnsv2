package dns

type (
	// An Option represents an OPT RR rdata value.
	// Basic usage for adding an option to an OPT RR:
	//
	//	opt := &OPT{Header: Header{Name: NewName(".")}}
	//	nsid := &NSID{ID: []byte("AA")}
	//	opt.Options = []Option{nsid}
	//
	Option interface {
		// Len returns the option's value length. This is excluding the option code and length (which is always 4 octets): len(o.Data()) = o.Len() + 4.
		Len() int
		// Data returns the option's values. The buffer returned is in wire format, all options require option code and length, this is prepended in the buffer.
		Data() []byte
		// String returns the string representation of the EDNS0 option.
		String() string
	}
)

// Supported EDNS0 Option Codes.
var (
	CodeNone = [2]byte{0, 0}
	CodeNSID = [2]byte{0, 3}
)

// OptionCode returns the option code of the Option.
func OptionCode(e Option) [2]byte {
	switch e.(type) {
	case *NSID:
		return CodeNSID
	}
	return CodeNone
}

func optionHeader(e Option) [4]byte {
	code := OptionCode(e)
	l := e.Len()
	return [4]byte{
		code[0],
		code[1],
		byte(l >> 8),
		byte(l),
	}
}

// NSID Option
type NSID struct {
	ID []byte // ID is a hex encoded string.
}

func (o *NSID) Len() int       { return len(o.ID) }
func (o *NSID) String() string { return string(o.ID) }
func (o *NSID) Data() []byte {
	header := optionHeader(o)
	return append(header[:], o.ID...)
}
