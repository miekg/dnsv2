package dnswire

import "testing"

func TestNameMarshal(t *testing.T) {
	name := Name{}.Marshal("miek.nl.")
	if x := name.String(); x != "miek.nl." {
		t.Fatalf("failed to marshal a dns name, expected %s, got %s", "miek.nl.", x)
	}
	name = Name{}.Marshal("miek.nl")
	if x := name.String(); x != "miek.nl." {
		t.Fatalf("failed to marshal a dns name, expected %s, got %s", "miek.nl.", x)
	}
	name = Name{}.Marshal(".")
	if x := name.String(); x != "." {
		t.Fatalf("failed to marshal a dns name, expected %s, got %s", ".", x)
	}
}
