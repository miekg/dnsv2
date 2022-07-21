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
