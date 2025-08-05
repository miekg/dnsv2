package dns

import (
	"encoding/binary"
	"iter"

	"github.com/miekg/dnsv2/dnswire"
)

// rrs() count the RR in sections that holds them: answer, ns, and extra, pseudo and question are different.
func (s section) rrs(m *Msg) iter.Seq[RR] {
	if m == nil || len(m.octets) == 0 {
		return func(yield func(RR) bool) { return }
	}
	off := s.start
	return func(yield func(RR) bool) {
		for {
			end := dnswire.Jump(m.octets, off)
			if end == 0 || end > s.end {
				break
			}
			typeoffset := dnswire.JumpName(m.octets, off)
			rrtype := dnswire.Type(binary.BigEndian.Uint16(m.octets[typeoffset:]))

			var rr RR
			if newRR, ok := TypeToRR[rrtype]; ok {
				rr = newRR()
			} else {
				rr = new(RFC3597)
			}
			buf := make([]byte, end-off)
			copy(buf, m.octets[off:end])
			rr.Octets(buf)
			off = end
			if !yield(rr) {
				return
			}
		}
	}
}

// len returns the number of RRs that are stored in this section. Again pseudo and question are different.
func (s section) len(m *Msg) int {
	if m == nil || len(m.octets) == 0 {
		return 0
	}
	l := 0
	off := s.start
	for {
		end := dnswire.Jump(m.octets, off)
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
func (a *Answer) RRs() iter.Seq[RR] { return a.section.rrs(a.Msg) }

// See [Answer.RRs].
func (n *Ns) RRs() iter.Seq[RR] { return n.section.rrs(n.Msg) }

// See [Answer.RRs].
func (e *Extra) RRs() iter.Seq[RR] { return e.section.rrs(e.Msg) }

// Len returns the number of RRs that are availble in this section.
func (a *Answer) Len() int { return a.section.len(a.Msg) }

// See [Answer.Len].
func (n *Ns) Len() int { return n.section.len(n.Msg) }

// See [Answer.Len].
func (e *Extra) Len() int { return e.section.len(e.Msg) }

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
			// end + 4 should match q.end actually.
			rrtype := dnswire.Type(binary.BigEndian.Uint16(q.Msg.octets[end:]))

			var rr RR
			if newRR, ok := TypeToRR[rrtype]; ok {
				rr = newRR()
			} else {
				rr = new(RFC3597)
			}
			// Also make room for the TTL and the rdlength (although not used).
			buf := make([]byte, (end-off)+4+2)
			copy(buf, q.Msg.octets[off:end+4])
			rr.Octets(buf)
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

// Append copies the RR to the question section. As the question section can only contain a single RR only the
// first RR is used. This copies the RR's octets into the message.
func (q *Question) Append(rr ...RR) {
	if len(rr) == 0 {
		return
	}
	octets := rr[0].Octets()
	// just append for now, later check for other stuff.
	end := dnswire.JumpName(octets, 0)
	end += 4
	q.octets = append(q.octets, make([]byte, end)...)
	copy(q.octets[MsgHeaderLen:], octets[0:end])
	q.Msg.Qdcount(1)
}
