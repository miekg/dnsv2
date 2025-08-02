package dns

import "github.com/miekg/dnsv2/dnswire"

// TypeToRR is a map of constructors for each RR type.
var TypeToRR = map[dnswire.Type]func() RR{
	TypeA:   func() RR { return new(A) },
	TypeMX:  func() RR { return new(MX) },
	TypeOPT: func() RR { return new(OPT) },
}
