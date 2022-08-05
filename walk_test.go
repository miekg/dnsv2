package dns

import (
	"errors"
	"testing"
)

func TestWalkForward(t *testing.T) {
	t.Parallel()
	m := &Msg{Buf: tmpbuf(www)}
	err := m.Walk(WalkForward, func(s Section, rr RR, i int) error {
		switch s {
		case Qd:
			if i == 0 && RRType(rr) != TypeA {
				t.Errorf("expected type %s for %d RR in section %s, got %s", TypeA, 0, s, RRType(rr))
			}
			if i > 0 {
				t.Errorf("too many (%d > 1) RRs in section %s", i, s)
			}
		case An:
			if i == 0 && RRType(rr) != TypeCNAME {
				t.Errorf("expected type %s for %d RR in section %s, got %s", TypeCNAME, 0, s, RRType(rr))
			}
			if i == 1 && RRType(rr) != TypeA {
				t.Errorf("expected type %s for %d RR in section %s, got %s", TypeA, 1, s, RRType(rr))
			}
			if i > 1 {
				t.Errorf("too many (%d > 2) RRs in section %s", i, s)
			}
		case Ar:
			if i == 0 && RRType(rr) != TypeOPT {
				t.Errorf("expected type %s for %d RR in section %s, got %s", TypeOPT, 0, s, RRType(rr))
				if i > 0 {
					t.Errorf("too many (%d > 1) RRs in section %s", i, s)
				}
			}
		default:
			t.Errorf("not expecting section %s", s)
		}
		return nil
	})
	if err != nil {
		t.Fatalf(err.Error())
	}
}

func TestWalkBackward(t *testing.T) {
	t.Parallel()
	m := &Msg{Buf: tmpbuf(www)}
	j := 0
	err := m.Walk(WalkBackward, func(s Section, rr RR, i int) error {
		if j == 0 && RRType(rr) != TypeOPT {
			t.Errorf("expected first RR type to be %s, got %s", TypeOPT, RRType(rr))
		}
		j++
		return nil
	})
	if err != nil {
		t.Fatalf(err.Error())
	}
}

// TestWalkAndStripOPT shows how to detect and remove the OPT record, so a) you can reuse the message buffer and b)
// slap a new OPT RR on it.
func TestWalkAndStripOPT(t *testing.T) {
	t.Parallel()
	m := &Msg{Buf: tmpbuf(reply)}
	pos := 0
	err := m.Walk(WalkBackward, func(s Section, rr RR, i int) error {
		if s == Ar && RRType(rr) == TypeOPT {
			pos = i
			return errors.New("found opt RR")
		}
		return nil
	})
	if err != nil {
		rrs, err := m.Strip(pos + 1)
		if err != nil {
			t.Fatalf(err.Error())
		}
		if len(rrs) != 1 {
			t.Errorf("expected to have stripped 1, got %d", len(rrs))
		}
		if x, ok := rrs[0].(*OPT); !ok {
			t.Errorf("expected to have OPT RR,got %T", x)
		}
		if m.Count(Ar) != 0 {
			t.Errorf("expected count to be %d, got %d", 0, m.Count(Ar))
		}
	}
}
