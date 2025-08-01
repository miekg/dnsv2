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
			// which RR type to make, need to the type from the octets
			// get rrtype from BYTES
			rrtype := dnswire.Type(15) // mx
			var rr RR
			if newRR, ok := TypeToRR[rrtype]; ok {
				rr = newRR()
				rr.Msg(s.msg)
			} else {
				// unknown
			}
			if !yield(rr) {
				return
			}
		}
	}
}
