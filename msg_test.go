package dns

import (
	"testing"

	"github.com/miekg/dnsv2/dnswire"
)

func TestMsgQuestionMX(t *testing.T) {
	mx := new(MX)
	mx.Name(dnswire.Name{}.Marshal("miek.nl"))
	mx.Class(ClassINET)

	msg := new(Msg)
	msg.Opcode(OpcodeQuery)
	q := NewSection(Question)
	q.Append(mx)

	t.Logf("%d %v\n", len(msg.Octets()), msg.Octets())
}
