package dns

import (
	"encoding/binary"
	"iter"

	"github.com/miekg/dnsv2/dnswire"
)

// RRs() count the RR in sections that holds them: answer, ns, and extra, pseudo and question are different.
func (s section) RRs() iter.Seq[RR] {
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

// Len returns the number of RRs that are stored in this section. Again pseudo and question are different.
func (s section) Len() int {
	if len(s.octets) == 0 {
		return 0
	}
	l := 0
	off := 0
	for {
		end := dnswire.Jump(s.octets, off)
		if end == 0 {
			break
		}
		l++
		off = end
	}
	return l
}

// RRs returns an interator the allows ranging over the RRs in s. Returned RRs are still tied to the DNS
// message they come from. This is to resolve compression pointers if they are present when calling rr.Name.
func (a *Answer) RRs() iter.Seq[RR] { return a.section.RRs() }

// Len returns the number of RRs that are stored in this section.
func (a *Answer) Len() int { return a.section.Len() }

// RRs returns an interator the allows ranging over the RRs in s. Returned RRs are still tied to the DNS
// message they come from. This is to resolve compression pointers if they are present when calling rr.Name.
func (n *Ns) RRs() iter.Seq[RR] { return n.section.RRs() }

// Len returns the number of RRs that are stored in this section.
func (n *Ns) Len() int { return n.section.Len() }

// RRs returns an interator the allows ranging over the RRs in s. Returned RRs are still tied to the DNS
// message they come from. This is to resolve compression pointers if they are present when calling rr.Name.
func (e *Extra) RRs() iter.Seq[RR] { return e.section.RRs() }

// Len returns the number of RRs that are stored in this section.
func (e *Extra) Len() int { return e.section.Len() }

// Append adds the RR (or RRs) to the section.
func (q *Question) Append(rr ...RR) {
	for _, r := range rr {
		octets := r.Octets()
		// set the type based on the RR type, and for the question we don't need to the TTL, so cut that off, as also the rdlength.
		end := dnswire.JumpName(octets, 0)
		i := RRToType(r)
		binary.BigEndian.PutUint16(octets[end:], uint16(i))
		end += 4
		q.octets = append(q.octets, octets[0:end]...)
	}
}
