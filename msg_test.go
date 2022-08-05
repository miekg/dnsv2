package dns

import (
	"net"
	"testing"
)

func TestRRQdDepletion(t *testing.T) {
	t.Parallel()
	m := &Msg{Buf: tmpbuf(query)}

	rr, err := m.RR(Qd)
	if err != nil {
		t.Errorf("failed to get RR: %s", err)
	}

	rr, err = m.RR(Qd)
	if rr != nil {
		t.Errorf("expected RR to be nil, but got %s", rr)
	}
}

func TestSetRRBufferResizing(t *testing.T) {
	t.Parallel()
	// this should not crash, as the buffer is resized.
	m := NewMsg(make([]byte, 40))
	rr := &A{
		Header{NewName("example.net."), IN, NewTTL(15)},
		NewIPv4(net.ParseIP("127.0.0.1")),
	}

	m.SetRR(Qd, rr)
	m.SetRR(An, rr)
	m.SetRR(Ns, rr)
	m.SetRR(Ar, rr)
}

func TestSetFlag(t *testing.T) {
	t.Parallel()
	m := NewMsg(make([]byte, 40))
	m.SetFlag(AA)
	if !m.Flag(AA) {
		t.Errorf("expected %s flag to be %t, got %t", AA, true, false)
	}
	m.SetFlag(AA, false)
	if m.Flag(AA) {
		t.Errorf("expected %s flag to be %t, got %t", AA, false, true)
	}
}

func TestSkip(t *testing.T) {
	t.Parallel()
	m := &Msg{Buf: tmpbuf(reply)}
	i := m.skipName(12)
	if i != 20 {
		t.Errorf("expected offset after qname %d, got %d", 20, i)
	}
	// First RR starts at 25 here.
	i = m.skipRR(25)
	if i != 63 {
		t.Errorf("expected offset after 1st skipRR %d, got %d", 63, i)
	}
	i = m.skipRR(i + 1)
	if i != 79 {
		t.Errorf("expected offset after 2nd skipRR %d, got %d", 79, i)
	}
	i = m.skipRR(i + 1)
	if i != 113 {
		t.Errorf("expected offset after 3rd skipRR %d, got %d", 113, i)
	}
	i = m.skipRR(i + 1)
	if i != 136 {
		t.Errorf("expected offset after 4th skipRR %d, got %d", 136, i)
	}
	i = m.skipRR(i + 1)
	if i != 157 {
		t.Errorf("expected offset after 5th skipRR %d, got %d", 157, i)
	}
	// OPT RR
	i = m.skipRR(i + 1)
	if i != 168 {
		t.Errorf("expected offset after OPT RR %d, got %d", 168, i)
	}
	i = m.skipRR(i + 1)
	if i != 0 {
		t.Errorf("expected offset after msg length %d, got %d", 0, i)
	}
}

func TestStrip(t *testing.T) {
	t.Parallel()
	m := &Msg{Buf: tmpbuf(reply)}
	m.Strip(2)
	if m.Count(Ar) != 0 || m.Count(An) != 4 {
		t.Errorf("expected AR count %d, got %d or expected AN count %d, got %d", 0, m.Count(Ar), 4, m.Count(An))
	}
}
