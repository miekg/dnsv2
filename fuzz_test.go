package dns

import (
	"os"
	"testing"
)

func FuzzMsgDecompress(f *testing.F) {
	testcases := []string{"dig-mx-miek.nl"}
	for _, tc := range testcases {
		buf, _ := os.ReadFile("testdata/" + tc)
		f.Add(buf)
	}
	f.Fuzz(func(t *testing.T, buf []byte) {
		// this should not crash
		msg := new(Msg)
		msg.Octets(buf)
		msg.Decompress()
		a := msg.Answer()
		a.Len()
	})
}
