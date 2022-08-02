package dns

import (
	"fmt"
	"testing"
)

func TestNameFromString(t *testing.T) {
	tcs := []struct {
		in  string
		out string
		err bool
	}{
		{".", "00", false},
		{"miek.nl.", "04miek02nl00", false},
		{"verylongexampleexampleexampleexample.example.org.", "36verylongexampleexampleexampleexample07example03org00", false},
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

/*
func TestBytes(t *testing.T) {
	rr := &A{
		Header{NewName("example.net."), ClassINET, NewTTL(15)},
		NewIPv4(net.ParseIP("127.0.0.1")),
	}

	wirebuf := Bytes(rr)
	fmt.Printf("This is its complete wireformat: %+v\n", wirebuf)
	// convert this back into an A record, via some convience function.
}
*/

func TestNameNext(t *testing.T) {
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
