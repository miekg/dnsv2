package dns

// In this file we define all the RRs we can handle, "go generate" will generate most methods for us.
// Supported tags:
//
// * `len` - take the len of the field instead of counting it as 1.
// * `-data` - skip this RR when generating the Data method, can be set on any field.
// * `-string` - skip this RR when generating the String method, can be set on any field.

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
)

var (
	// Valid Classes.
	IN   = Class{0, 1}
	NONE = Class{0, 254}
	ANY  = Class{0, 255}

	// Supported RR Types.
	TypeNone  = Type{0, 0}
	TypeA     = Type{0, 1}
	TypeNS    = Type{0, 2}
	TypeCNAME = Type{0, 5}
	TypeSOA   = Type{0, 6}
	TypePTR   = Type{0, 12}
	TypeMX    = Type{0, 15}
	TypeOPT   = Type{0, 41}
)

// A RR. See RFC 1035.
type A struct {
	Header
	A [4]byte `dns:"-string"`
}

func (rr *A) String() string {
	return TypeA.String() + "\t" + net.IP{rr.A[0], rr.A[1], rr.A[2], rr.A[3]}.String()
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
	Exchange   Name
}

func (rr *MX) Write(msg []byte, offset, n int) error {
	rr.Preference[0] = msg[offset]
	rr.Preference[1] = msg[offset+1]
	name, _, err := unpackName(msg, offset+2)
	if err != nil {
		return err
	}
	rr.Exchange = name
	return nil
}

// CNAME RR. See RFC 1035.
type CNAME struct {
	Header
	Target Name
}

func (rr *CNAME) Write(msg []byte, offset, n int) error {
	name, _, err := unpackName(msg, offset)
	if err != nil {
		return err
	}
	rr.Target = name
	return nil
}

// NS RR. See RFC 1035.
type NS struct {
	Header
	Target Name
}

func (rr *NS) Write(msg []byte, offset, n int) error {
	name, _, err := unpackName(msg, offset)
	if err != nil {
		return err
	}
	rr.Target = name
	return nil
}

// PTR RR. See RFC 1035.
type PTR struct {
	Header
	Target Name
}

func (rr *PTR) Write(msg []byte, offset, n int) error {
	name, _, err := unpackName(msg, offset)
	if err != nil {
		return err
	}
	rr.Target = name
	return nil
}

// SOA RR. See RFC 1035.
type SOA struct {
	Header
	Ns      Name
	Mbox    Name
	Serial  [4]byte
	Refresh [4]byte
	Retry   [4]byte
	Expire  [4]byte
	MinTTL  [4]byte
}

func (rr *SOA) Write(msg []byte, offset, n int) error {
	name, offset, err := unpackName(msg, offset)
	if err != nil {
		return err
	}
	rr.Ns = name
	name, offset, err = unpackName(msg, offset+1)
	if err != nil {
		return err
	}
	rr.Mbox = name
	offset++

	rr.Serial[0] = msg[offset]
	rr.Serial[1] = msg[offset+1]
	rr.Serial[2] = msg[offset+2]
	rr.Serial[3] = msg[offset+3]

	rr.Refresh[0] = msg[offset+4]
	rr.Refresh[1] = msg[offset+5]
	rr.Refresh[2] = msg[offset+6]
	rr.Refresh[3] = msg[offset+7]

	rr.Retry[0] = msg[offset+8]
	rr.Retry[1] = msg[offset+9]
	rr.Retry[2] = msg[offset+10]
	rr.Retry[3] = msg[offset+11]

	rr.Expire[0] = msg[offset+12]
	rr.Expire[1] = msg[offset+13]
	rr.Expire[2] = msg[offset+14]
	rr.Expire[3] = msg[offset+15]

	rr.MinTTL[0] = msg[offset+16]
	rr.MinTTL[1] = msg[offset+17]
	rr.MinTTL[2] = msg[offset+18]
	rr.MinTTL[3] = msg[offset+19]

	return nil
}

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
