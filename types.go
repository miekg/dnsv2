package dns

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
)

var (
	// Valid Classes.
	ClassNONE = Class{0, 254}
	ClassINET = Class{0, 1}
	classANY  = Class{0, 255}

	// Supported RR Types.
	TypeNone = Type{0, 0}
	TypeA    = Type{0, 1}
	TypeMX   = Type{0, 15}
	TypeOPT  = Type{0, 41}
)

// A RR. See RFC 1035.
type A struct {
	Header
	A [4]byte
}

func (rr *A) Hdr() *Header { return &rr.Header }
func (rr *A) Len() int     { return 1 }
func (rr *A) String() string {
	return TypeToString[TypeA] + "\t" + net.IP{rr.A[0], rr.A[1], rr.A[2], rr.A[3]}.String()
}

func (rr *A) Data(i int) []byte {
	if i != 0 {
		return nil
	}
	return rr.A[:]
}

func (rr *A) Write(msg []byte, offset, n int) error {
	if offset+n > len(msg) {
		return &WireError{fmt.Errorf("buffer size too small, need %d, got %d", offset+n, len(msg))}
	}
	if n != 4 {
		return &WireError{fmt.Errorf("rdata length for %s, must be %d, got %d", RRType(rr), 4, n)}
	}
	rr.A[0] = msg[offset]
	rr.A[1] = msg[offset+1]
	rr.A[2] = msg[offset+2]
	rr.A[3] = msg[offset+3]
	return nil
}

// MX RR. See RFC 1035.
type MX struct {
	Header
	Preference [2]byte
	Mx         Name
}

func (rr *MX) Hdr() *Header { return &rr.Header }
func (rr *MX) Len() int     { return 2 }
func (rr *MX) String() string {
	prio := binary.BigEndian.Uint16(rr.Preference[:])
	return TypeToString[TypeMX] + "\t" + strconv.FormatUint(uint64(prio), 10) + " " + rr.Mx.String()
}

func (rr *MX) Data(i int) []byte {
	if i < 0 || i > 2 {
		return nil
	}
	switch i {
	case 0:
		return rr.Preference[:]
	case 1:
		return rr.Name
	}
	return nil
}

func (rr *MX) Write(msg []byte, offset, n int) error {
	// TODO: WireErrors here.
	// first two bytes are preference, rest is domain name, with possible compression pointers.
	rr.Preference[0] = msg[offset]
	rr.Preference[1] = msg[offset+1]
	name, _, err := unpackName(msg, offset+2)
	if err != nil {
		return err
	}
	rr.Mx = name
	return nil
}

/*
type CNAME struct {
	Hdr    Header
	Target Name
}
*/

// Unknown represents an unknown/generic RR. See RFC 3597.
type Unknown struct {
	Header
	Type           // Type holds the type number of the unknown type we're holding.
	Unknown []byte // Data is as-is.
}

func (rr *Unknown) Hdr() *Header { return &rr.Header }
func (rr *Unknown) Len() int     { return 1 }
func (rr *Unknown) String() string {
	t := binary.BigEndian.Uint16(rr.Type[:])
	l := len(rr.Unknown)
	if l == 0 {
		return "TYPE" + strconv.FormatUint(uint64(t), 10) + "\t\\# 0"
	}
	return "TYPE" + strconv.FormatUint(uint64(t), 10) + "\t\\# " + strconv.FormatUint(uint64(l), 10) + " " + hex.EncodeToString(rr.Unknown)
}

func (rr *Unknown) Data(i int) []byte {
	if i != 1 {
		return nil
	}
	return rr.Unknown
}

func (rr *Unknown) Write(msg []byte, offset, n int) error {
	if offset+n > len(msg) {
		return &WireError{fmt.Errorf("buffer size too small, need %d, got %d", offset+n, len(msg))}
	}
	rr.Unknown = msg[offset : offset+n]
	return nil
}

// RRType returns the type of the RR.
func RRType(rr RR) Type {
	switch rr.(type) {
	case *A:
		return TypeA
	case *MX:
		return TypeMX
	case *OPT:
		return TypeOPT
	}
	return TypeNone
}

var typeToRR = map[Type]func() RR{
	TypeA:   func() RR { return new(A) },
	TypeMX:  func() RR { return new(MX) },
	TypeOPT: func() RR { return new(OPT) },
}

var TypeToString = map[Type]string{
	TypeA:   "A",
	TypeMX:  "MX",
	TypeOPT: "OPT",
}

var (
	_ RR = new(A)
	_ RR = new(MX)
	_ RR = new(OPT)
)
