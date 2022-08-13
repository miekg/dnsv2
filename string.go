package dns

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

func (s Section) String() string {
	switch s {
	case Qd:
		return "QUESTION"
	case An:
		return "ANSWER"
	case Ns:
		return "AUTHORITY"
	case Ar:
		return "ADDITIONAL"
	}
	return ""
}

func (t TTL) String() string {
	i := binary.BigEndian.Uint32(t[:])
	// avoid pulling the machinary from fmt.Printf
	switch {
	case i < 10:
		return "    " + strconv.FormatUint(uint64(i), 10)
	case i < 100:
		return "   " + strconv.FormatUint(uint64(i), 10)
	case i < 1000:
		return "  " + strconv.FormatUint(uint64(i), 10)
	default:
		return " " + strconv.FormatUint(uint64(i), 10)
	}
}

func (n Name) GoString() string {
	if len(n) == 0 {
		return ""
	}
	if n[0] == 0 {
		return "00"
	}
	b := &strings.Builder{}
	for i := 0; i < len(n); {
		v := int(n[i])
		ll := strconv.Itoa(v)
		if v < 10 {
			b.WriteString("0")
		}
		b.WriteString(ll)
		// i+1 ... i+ll is the labels "text"
		b.Write(n[i+1 : i+1+v])
		i += v + 1
	}
	return b.String()
}

func (n Name) String() string {
	if len(n) == 0 {
		return ""
	}
	if n[0] == 0 {
		return "."
	}
	b := &strings.Builder{}
	for i := 0; i < len(n); {
		v := int(n[i])
		if i > 0 { // don't want to start with a dot
			b.WriteString(".")
		}
		// i+1 ... i+ll is the labels "text"
		b.Write(n[i+1 : i+1+v])
		i += v + 1
	}

	return b.String()
}

func (h *Header) String() string {
	return h.Name.String() + " \t" + h.TTL.String() + " " + h.Class.String()
}

// StringOPT returns the header as needed for rendering an OPT header.
func (h *Header) OPTString(opt *OPT) string {
	b := &strings.Builder{}
	b.WriteString(";; EDNS: version: ")
	b.WriteString(fmt.Sprintf("%d", opt.Version()))
	b.WriteString(", flags: ")
	b.WriteString(fmt.Sprintf("udp: %d", opt.Size()))
	if d := opt.Do(); d {
		b.WriteString("; do\n")
	}
	return b.String()
}

// QdString returns the header as needed for rendering an question section.
func (h *Header) QdString(rr RR) string {
	b := &strings.Builder{}
	b.WriteString(rr.Hdr().Name.String())
	b.WriteString(" ")
	b.WriteString(rr.Hdr().Class.String())
	b.WriteString(" ")
	b.WriteString(RRToType(rr).String())
	b.WriteString("\n")
	return b.String()
}
