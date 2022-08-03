package dns

import (
	"encoding/binary"
)

// WalkFunc is the type of the function called by Walk to visit each Header. RR will only contain the header, no rdata
// unpacked. The int parameter is where in the section this RR sits.
type WalkFunc func(s Section, rr RR, i int) error

// WalkDirection tells in what order to walk the message.
type WalkDirection int

const (
	WalkForward WalkDirection = iota
	WalkBackward
)

// Walk walks the section s in the message m in the direction of d. Each rr is filtered by fn. If WalkFunc returns an error the walk is
// stopped. Note due to DNS messages are structed an [WalkBackward] requires to walk forward and then backwards.
func (m *Msg) Walk(d WalkDirection, fn WalkFunc) (err error) {
	m.index() // reset any reads

	// TODO: Walk backward allocates...

	name := make([]byte, 12)
	i := int(m.r[Qd])

	type reverse struct {
		s  Section
		rr RR
		i  int
	}
	var stack []reverse
	if d == WalkBackward {
		stack = make([]reverse, 0, m.Count(Qd)+m.Count(An)+m.Count(Ns)+m.Count(Ar))
	}

	for s := Qd; s <= Ar; s++ {
		for m.count[s] < m.Count(s) {
			// overlap with index(), factor this out somehow.
			if name, i, err = unpackName(m.Buf, i, name); err != nil {
				return err
			}

			i++
			typ := Type{m.Buf[i], m.Buf[i+1]}
			rrfunc, ok := typeToRR[typ]
			if !ok {
				rrfunc = func() RR { return new(Unknown) }
			}
			i += 2

			rr := rrfunc()
			rr.Hdr().Name = name

			if rfc3597, ok := rr.(*Unknown); ok {
				rfc3597.Type = typ
			}

			// Class
			rr.Hdr().Class[0], rr.Hdr().Class[1] = m.Buf[i], m.Buf[i+1]
			i += 2

			if s == Qd {
				switch d {
				case WalkForward:
					if err := fn(s, rr, int(m.count[s])); err != nil {
						return err
					}
				case WalkBackward:
					// copy functions??
					newname := make([]byte, len(rr.Hdr().Name))
					copy(newname, rr.Hdr().Name)
					rr.Hdr().Name = newname
					stack = append(stack, reverse{s, rr, int(m.count[s])})
				}
				m.count[s]++
				continue
			}

			// TTL
			rr.Hdr().TTL[0] = m.Buf[i]
			rr.Hdr().TTL[1] = m.Buf[i+1]
			rr.Hdr().TTL[2] = m.Buf[i+2]
			rr.Hdr().TTL[3] = m.Buf[i+3]
			i += 4

			// Rdata length
			rdl := int(binary.BigEndian.Uint16(m.Buf[i:]))
			i += 2
			i += rdl

			switch d {
			case WalkForward:
				if err := fn(s, rr, int(m.count[s])); err != nil {
					return err
				}
			case WalkBackward:
				// copy functions??
				newname := make([]byte, len(rr.Hdr().Name))
				copy(newname, rr.Hdr().Name)
				rr.Hdr().Name = newname

				stack = append(stack, reverse{s, rr, int(m.count[s])})

			}
			m.count[s]++
		}
	}
	if d == WalkForward {
		return nil
	}

	for i := len(stack) - 1; i >= 0; i-- {
		if err := fn(stack[i].s, stack[i].rr, stack[i].i); err != nil {
			return err
		}
	}

	return nil
}
