package dns

import (
	"encoding/binary"
	"iter"

	"github.com/miekg/dnsv2/dnswire"
)

// NewSection returns a new section with the appriate message section set.
func NewSection(which uint8) *Section { return &Section{which: which} }

// RRs returns an interator the allows ranging over the RRs in s. Returned RRs are still tied to the DNS
// message they come from. This is to resolve compression pointers if they are present when calling rr.Name.
func (s *Section) RRs() iter.Seq[RR] {
	off := 0
	return func(yield func(RR) bool) {
		for {
			end := dnswire.Jump(s.octets, off)
			if end == 0 {
				break
			}
			rrtype := dnswire.RRType(s.octets, off)
			var rr RR
			if newRR, ok := TypeToRR[rrtype]; ok {
				rr = newRR()
			} else {
				rr = new(RFC3597)
			}
			rr.Msg(s.msg)
			rr.Octets(s.octets[off:end])
			off = end
			if !yield(rr) {
				return
			}
		}
	}
}

// Len returns the number of RRs that are stored in this section.
func (s *Section) Len() int {
	if len(s.octets) == 0 {
		return 0
	}
	l := 0
	off := 0
	for {
		l++
		end := dnswire.Jump(s.octets, off)
		if end == 0 {
			break
		}
		off = end
	}
	return l
}

// Append adds the RR (or RRs) to the section. If the Section's section is not defined, it is assumed to be
// Question.
func (s *Section) Append(rr ...RR) {
	switch s.which {
	case Question:
		for _, r := range rr {
			octets := r.Octets()
			// set the type based on the RR type, and for the question we don't need to the TTL, so cut that
			// off, as also the rdlength.
			end := dnswire.JumpName(octets, 0)
			i := RRToType(r)
			binary.BigEndian.PutUint16(octets[end:], uint16(i))
			end += 4
			s.octets = append(s.octets, octets[0:end]...)
		}
	}
}
