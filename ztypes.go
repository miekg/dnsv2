package dns

// autogen

import "github.com/miekg/dnsv2/dnswire"

// TypeToRR is a map of constructors for each RR type.
var TypeToRR = map[dnswire.Type]func() RR{
	TypeA:   func() RR { return new(A) },
	TypeMX:  func() RR { return new(MX) },
	TypeOPT: func() RR { return new(OPT) },
}

// RRToType is the reverse of TypeToRR, implemented as a function.
func RRToType(rr RR) dnswire.Type {
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

// TypeToString is a map of strings for each RR type.
var TypeToString = map[dnswire.Type]string{
	TypeA:   "A",
	TypeMX:  "MX",
	TypeOPT: "OPT",
}
