package dns

import (
	"iter"

	"github.com/miekg/dnsv2/dnswire"
)

// RRs returns an interator the allows ranging over the RRs in s. Returned RRs are still tied to the DNS
// message they come from. This is to resolve compression pointers if they are present when calling rr.Name.
func (s Section) RRs() iter.Seq[RR] {
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
