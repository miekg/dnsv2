package dns

import (
	"os"
	"testing"

	"github.com/miekg/dnsv2/dnswire"
)

func TestMsgQuestionMX(t *testing.T) {
	mx := new(MX)
	mx.Name(dnswire.Name{}.Marshal("miek.nl"))
	mx.Class(ClassINET)
	t.Logf("%d %v\n", 10, mx.String())

	msg := new(Msg)
	msg.Opcode(OpcodeQuery)
	q := new(Question)
	q.Append(mx)
	t.Logf("%d %v\n", len(q.octets), q.octets)
	msg.Question(q)

	t.Logf("%d %v\n", len(msg.Octets()), msg.Octets())
}

func TestMsgBinary(t *testing.T) {
	buf, err := os.ReadFile("testdata/dig-mx-miek.nl")
	if err != nil {
		t.Fatal(err)
	}
	msg := new(Msg)
	msg.Octets(buf)

	a := msg.Answer()
	if a.Len() != 5 {
		t.Fatalf("expected %d RRs in the answer section, got %d", 5, a.Len())
	}
	t.Logf("%d %v\n", len(a.octets), a.octets)
}
