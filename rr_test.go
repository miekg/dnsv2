package dns

import (
	"fmt"
	"strings"
	"testing"
)

func TestNameFromString(t *testing.T) {
	t.Parallel()
	tcs := []struct {
		in  string
		out string
		err bool
	}{
		{".", "00", false},
		{"miek.nl.", "04miek02nl00", false},
		{"verylongexampleexampleexampleexample.example.org.", "36verylongexampleexampleexampleexample07example03org00", false},
		{"..", "", true}, // empty label is illegal
		{strings.Repeat("abcdef", 10) + "123.nl.", "63abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef12302nl00", false},
		{strings.Repeat("abcdef", 10) + "1234.nl.", "", true}, // 64 label length
	}

	for _, tc := range tcs {
		name := NewName(tc.in)
		if name == nil && !tc.err {
			t.Errorf("expected [%s] to result in an error, got none", tc.in)
			continue
		}
		if tc.err {
			continue
		}
		if x := fmt.Sprintf("%#v", name); x != tc.out {
			t.Errorf("expected [%s], got [%s]", tc.out, x)
		}
		if x := name.String(); x != tc.in {
			t.Errorf("expected [%s], got [%s]", tc.in, x)
		}
	}
}

func TestNameNext(t *testing.T) {
	t.Parallel()
	n := NewName("www.a.miek.nl.")

	for j, i, stop := 0, 0, false; !stop; i, stop = n.Next(i) {
		if len(n[i:]) == 1 {
			break
		}
		name := Name(n[i:]).GoString()
		switch j {
		case 0:
			if x := "03www01a04miek02nl00"; name != x {
				t.Errorf("expected %s, got %s", x, name)
			}
		case 1:
			if x := "01a04miek02nl00"; name != x {
				t.Errorf("expected %s, got %s", x, name)
			}
		case 2:
			if x := "04miek02nl00"; name != x {
				t.Errorf("expected %s, got %s", x, name)
			}
		case 3:
			if x := "02nl00"; name != x {
				t.Errorf("expected %s, got %s", x, name)
			}
		default:
			t.Fatalf("expected %d iterations, got %d", 4, j)

		}
		j++
	}
}

func TestNameRoot(t *testing.T) {
	t.Parallel()
	m := NewMsg(make([]byte, 20))

	n := NewName(".")
	rr := &MX{Header: Header{Name: n, Class: IN}}
	m.SetRR(Qd, rr)

	if m.Buf[12] != 0 {
		t.Errorf("expected byte 12 to be 0, got %d", m.Buf[12])
	}
	if m.Len() != 17 {
		t.Errorf("expected message length to be %d, got %d", 17, m.Len())
	}
}
