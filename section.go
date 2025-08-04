package dns

import (
	"encoding/binary"
	"iter"

	"github.com/miekg/dnsv2/dnswire"
)

// rrs() count the RR in sections that holds them: answer, ns, and extra, pseudo and question are different.
func (s Section) rrs() iter.Seq[RR] {
	if s.Msg == nil || len(s.Msg.octets) == 0 {
		return func(yield func(RR) bool) { return }
	}
	off := s.start
	return func(yield func(RR) bool) {
		for {
			end := dnswire.Jump(s.Msg.octets, off)
			if end == 0 || end > s.end {
				break
			}
			typeoffset := dnswire.JumpName(s.Msg.octets, off)
			rrtype := dnswire.Type(binary.BigEndian.Uint16(s.Msg.octets[typeoffset:]))

			var rr RR
			if newRR, ok := TypeToRR[rrtype]; ok {
				rr = newRR()
			} else {
				rr = new(RFC3597)
			}
			rr.Octets(s.Msg.octets[off:end])
			off = end
			if !yield(rr) {
				return
			}
		}
	}
}

// len returns the number of RRs that are stored in this section. Again pseudo and question are different.
func (s Section) len() int {
	if s.Msg == nil || len(s.Msg.octets) == 0 {
		return 0
	}
	l := 0
	off := s.start
	for {
		end := dnswire.Jump(s.Msg.octets, off)
		if end == 0 || end > s.end {
			break
		}
		l++
		off = end
	}
	return l
}

// Implement the following:
// Len, RRs() (=All), see godoc slices: Delete(i, j int), Index, Insert, Replace(i, j int), AppendSeq, Append

// RRs returns an iterator the allows ranging over the RRs in s. Returned RRs are still tied to the DNS
// message they come from. This is to resolve compression pointers if they are present when calling rr.Name.
func (a *Answer) RRs() iter.Seq[RR] { return a.Section.rrs() }

// See [Answer.RRs].
func (n *Ns) RRs() iter.Seq[RR] { return n.Section.rrs() }

// See [Answer.RRs].
func (e *Extra) RRs() iter.Seq[RR] { return e.Section.rrs() }

// Len returns the number of RRs that are availble in this section.
func (a *Answer) Len() int { return a.Section.len() }

// See [Answer.Len].
func (n *Ns) Len() int { return n.Section.len() }

// See [Answer.Len].
func (e *Extra) Len() int { return e.Section.len() }

// RRs() returns an iterator that holds the one "RR" from the question section.
func (q *Question) RRs() iter.Seq[RR] {
	if q.Msg == nil || len(q.Msg.octets) == 0 {
		return func(yield func(RR) bool) { return }
	}
	off := q.start
	return func(yield func(RR) bool) {
		for {
			end := dnswire.JumpName(q.Msg.octets, off)
			if end == 0 || end+4 > q.end {
				break
			}
			rrtype := dnswire.Type(binary.BigEndian.Uint16(q.Msg.octets[end:]))

			var rr RR
			if newRR, ok := TypeToRR[rrtype]; ok {
				rr = newRR()
			} else {
				rr = new(RFC3597)
			}
			rr.Octets(q.Msg.octets[off:end])
			off = end
			if !yield(rr) {
				return
			}
			break // there is only one
		}
	}
}

// Len returns the number of RR in the question section. It return 1 or 0.
func (q *Question) Len() int {
	if q.Msg == nil || len(q.Msg.octets) == 0 {
		return 0
	}
	return 1
}

// Append adds the RR to the section. If multiple RRs are given only the first one will be added.
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
