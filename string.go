package dns

import (
	gob "encoding/binary"
	"strconv"
	"strings"
)

func (c Class) GoString() string {
	switch c {
	case ClassINET:
		return "IN"
	}
	return "NONE"
}

func (c Class) String() string { return c.GoString() }

func (t TTL) GoString() string {
	i := gob.BigEndian.Uint32(t[:])
	return strconv.FormatUint(uint64(i), 10)
}

func (t TTL) String() string { return t.GoString() }

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

func (h Header) GoString() string {
	return h.Name.GoString() + " " + h.TTL.GoString() + " " + h.Class.GoString()
}

func (h Header) String() string {
	return h.Name.String() + " " + h.TTL.String() + " " + h.Class.String()
}
