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

	for i, stop := 0, false; !stop; i, stop = n.Next(i) {
		if len(n[i:]) == 1 {
			break
		}
		println(stop, i, Name(n[i:]).GoString())
	}
}
