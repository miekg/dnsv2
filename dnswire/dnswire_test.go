package dnswire

import (
	"testing"
)

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

// These are the 5 MX records of miek.nl, with compression pointers but we don't care for these tests.
// ;; ANSWER SECTION:
// miek.nl.                10596   IN      MX      1 aspmx.l.google.com.
// miek.nl.                10596   IN      MX      10 aspmx3.googlemail.com.
// miek.nl.                10596   IN      MX      10 aspmx2.googlemail.com.
// miek.nl.                10596   IN      MX      5 alt2.aspmx.l.google.com.
// miek.nl.                10596   IN      MX      5 alt1.aspmx.l.google.com.
// We start on the first RR.
var mx = []byte{
	0xc0, 0xc, 0x0, 0xf, 0x0, 0x1, 0x0, 0x0, 0x54, 0x60, 0x0, 0x19, 0x0, 0xa, 0x6, // 0-14
	0x61, 0x73, 0x70, 0x6d, 0x78, 0x32, 0xa, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // 15-27
	0x6d, 0x61, 0x69, 0x6c, 0x3, 0x63, 0x6f, 0x6d, 0x0, 0xc0, 0xc, 0x0, 0xf, 0x0, // 28-41
	0x1, 0x0, 0x0, 0x54, 0x60, 0x0, 0x18, 0x0, 0x5, 0x4, 0x61, 0x6c, 0x74, 0x32, // 42-55
	0x5, 0x61, 0x73, 0x70, 0x6d, 0x78, 0x1, 0x6c, 0x6, 0x67, 0x6f, 0x6f, 0x67, // 56-68
	0x6c, 0x65, 0xc0, 0x39, 0xc0, 0xc, 0x0, 0xf, 0x0, 0x1, 0x0, 0x0, 0x54, 0x60, // 69-82
	0x0, 0x4, 0x0, 0x1, 0xc0, 0x51, 0xc0, 0xc, 0x0, 0xf, 0x0, 0x1, 0x0, 0x0, 0x54, // 83-97
	0x60, 0x0, 0x9, 0x0, 0x5, 0x4, 0x61, 0x6c, 0x74, 0x31, 0xc0, 0x51, 0xc0, 0xc, // 98-111
	0x0, 0xf, 0x0, 0x1, 0x0, 0x0, 0x54, 0x60, 0x0, 0xb, 0x0, 0xa, 0x6, 0x61, 0x73, // 112-126
	0x70, 0x6d, 0x78, 0x33, 0xc0, 0x2e, // 127-132
}

func TestJump(t *testing.T) {
	j := Jump(mx, 0)
	if j != 37 { // This is next to 0x0, on 0xC0 which is the pointer for miek.nl.
		t.Fatalf("expecting next RR to start on %d, got %d", 37, j)
	}
	j = Jump(mx, j)
	if j != 73 {
		t.Fatalf("expecting next RR to start on %d, got %d", 73, j)
	}
	// we expect 5,rr, got 2, so 3 more jumps
	j = Jump(mx, j)
	j = Jump(mx, j)
	j = Jump(mx, j)
	if j != 133 {
		t.Fatalf("expecting next RR to start on %d, got %d", 133, j)
	}
	j = Jump(mx, j)
	if j != 0 {
		t.Fatalf("expecting Jump to return %d, got %d", 0, j)
	}
}

func TestJumpName(t *testing.T) {
	// mx starts with a pointer.
	j := JumpName(mx, 0)
	if j != 2 {
		t.Fatalf("expecting name to have ended just before %d, got %d", 2, j)
	}
	// on off 56 the aspmx.l.google.com. name starts
	j = JumpName(mx, 56)
	if j != 73 {
		t.Fatalf("expecting name to have ended just before %d, got %d", 73, j)
	}
}
