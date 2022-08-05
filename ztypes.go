// Code generated by "go run types_generate.go"; Edits will be lost.

package dns

import (
	"encoding/binary"
	"strconv"
)

var typeToRR = map[Type]func() RR{
	TypeA:     func() RR { return new(A) },
	TypeCNAME: func() RR { return new(CNAME) },
	TypeMX:    func() RR { return new(MX) },
	TypeNS:    func() RR { return new(NS) },
	TypeOPT:   func() RR { return new(OPT) },
	TypePTR:   func() RR { return new(PTR) },
	TypeSOA:   func() RR { return new(SOA) },
}

var (
	_ RR = new(A)
	_ RR = new(CNAME)
	_ RR = new(MX)
	_ RR = new(NS)
	_ RR = new(OPT)
	_ RR = new(PTR)
	_ RR = new(SOA)
)

func (rr *A) Hdr() *Header     { return &rr.Header }
func (rr *CNAME) Hdr() *Header { return &rr.Header }
func (rr *MX) Hdr() *Header    { return &rr.Header }
func (rr *NS) Hdr() *Header    { return &rr.Header }
func (rr *OPT) Hdr() *Header   { return &rr.Header }
func (rr *PTR) Hdr() *Header   { return &rr.Header }
func (rr *SOA) Hdr() *Header   { return &rr.Header }

// RRType returns the type of the RR.
func RRType(rr RR) Type {
	switch rr.(type) {
	case *A:
		return TypeA
	case *CNAME:
		return TypeCNAME
	case *MX:
		return TypeMX
	case *NS:
		return TypeNS
	case *OPT:
		return TypeOPT
	case *PTR:
		return TypePTR
	case *SOA:
		return TypeSOA
	}
	return TypeNone
}

func (t Type) String() string {
	switch t {
	case TypeA:
		return "A"
	case TypeCNAME:
		return "CNAME"
	case TypeMX:
		return "MX"
	case TypeNS:
		return "NS"
	case TypeOPT:
		return "OPT"
	case TypePTR:
		return "PTR"
	case TypeSOA:
		return "SOA"
	}
	i := binary.BigEndian.Uint16(t[:])
	return "TYPE" + strconv.FormatUint(uint64(i), 10)
}
func (rr *A) Len() int {
	return 1
}
func (rr *CNAME) Len() int {
	return 1
}
func (rr *MX) Len() int {
	return 2
}
func (rr *NS) Len() int {
	return 1
}
func (rr *OPT) Len() int {
	return 0 + len(rr.Options)
}
func (rr *PTR) Len() int {
	return 1
}
func (rr *SOA) Len() int {
	return 7
}
func (rr *A) Data(i int) []byte {
	switch i {
	case 0:
		return rr.A[:]
	}
	return nil
}
func (rr *CNAME) Data(i int) []byte {
	switch i {
	case 0:
		return rr.Target
	}
	return nil
}
func (rr *MX) Data(i int) []byte {
	switch i {
	case 0:
		return rr.Preference[:]
	case 1:
		return rr.Exchange
	}
	return nil
}
func (rr *NS) Data(i int) []byte {
	switch i {
	case 0:
		return rr.Target
	}
	return nil
}
func (rr *PTR) Data(i int) []byte {
	switch i {
	case 0:
		return rr.Target
	}
	return nil
}
func (rr *SOA) Data(i int) []byte {
	switch i {
	case 0:
		return rr.Ns
	case 1:
		return rr.Mbox
	case 2:
		return rr.Serial[:]
	case 3:
		return rr.Refresh[:]
	case 4:
		return rr.Retry[:]
	case 5:
		return rr.Expire[:]
	case 6:
		return rr.MinTTL[:]
	}
	return nil
}

func (r Rcode) String() string {
	switch r {
	case RcodeFormErr:
		return "FORMERR"
	case RcodeNXDomain:
		return "NXDOMAIN"
	case RcodeNoError:
		return "NOERROR"
	case RcodeNotImp:
		return "NOTIMP"
	case RcodeRefused:
		return "REFUSED"
	case RcodeServFail:
		return "SERVFAIL"
	}
	return ""
}

func (o Opcode) String() string {
	switch o {
	case OpcodeIQuery:
		return "IQUERY"
	case OpcodeNotify:
		return "NOTIFY"
	case OpcodeQuery:
		return "QUERY"
	case OpcodeStatus:
		return "STATUS"
	case OpcodeUpdate:
		return "UPDATE"
	}
	return ""
}

func (f Flag) String() string {
	switch f {
	case AA:
		return "aa"
	case AD:
		return "ad"
	case CD:
		return "cd"
	case QR:
		return "qr"
	case RA:
		return "ra"
	case RD:
		return "rd"
	case TC:
		return "tc"
	case Z:
		return "z"
	}
	return ""
}

func (c Class) String() string {
	switch c {
	case ANY:
		return "ANY"
	case IN:
		return "IN"
	case NONE:
		return "NONE"
	}
	i := binary.BigEndian.Uint16(c[:])
	return "CLASS" + strconv.FormatUint(uint64(i), 10)
}
