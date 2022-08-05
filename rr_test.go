package dns

import (
	"fmt"
	"testing"
)

func TestNameFromString(t *testing.T) {
	t.Parallel()
	tcs := []struct {
		in  string
		out string
	}{
		{".", "00"},
		{"miek.nl.", "04miek02nl00"},
		{"verylongexampleexampleexampleexample.example.org.", "36verylongexampleexampleexampleexample07example03org00"},
	}

	for _, tc := range tcs {
		name := NewName(tc.in)
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
