package dns

import (
	"encoding/binary"
)

// WalkFunc is the type of the function called by Walk to visit each RR. This RR will only have its header populated, no
// no rdata is unpacked. The integer is the index of this RR in its section.
type WalkFunc func(s Section, rr RR, i int) error

// WalkDirection tells in what order to walk the message.
type WalkDirection int

const (
	WalkForward WalkDirection = iota
	WalkBackward
)

// Walk walks the section s in the message m in the direction of d. Each rr is filtered by fn. If WalkFunc returns an
// error the walk is stopped. Note due to DNS messages are structed an [WalkBackward] requires to walk forward and then
// backwards.
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

			var typ Type
			i++
			if typ, i, err = unpackType(m.Buf, i); err != nil {
				return err
			}
			rr := rrFromType(typ)
			rr.Hdr().Name = name

			if rr.Hdr().Class, i, err = unpackClass(m.Buf, i); err != nil {
				return err
			}

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

			if rr.Hdr().TTL, i, err = unpackTTL(m.Buf, i); err != nil {
				return err
			}

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
