package dns

import (
	"os"
	"testing"
)

func TestDecompress(t *testing.T) {
	buf, _ := os.ReadFile("testdata/dig-mx-miek.nl")
	msg := new(Msg)
	msg.Octets(buf)
	t.Logf("   Msg %d %v\n", len(msg.Octets()), msg.Octets())

	msg.Decompress()
	// figure out a good test.

	t.Logf("   Msg %d %v\n", len(msg.Octets()), msg.Octets())
}
