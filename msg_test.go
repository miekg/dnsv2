package dns

import (
	"testing"

	"github.com/miekg/dnsv2/dnswire"
)

func TestMsgQuestionMX(t *testing.T) {
	mx := new(MX)
	mx.Name(dnswire.Name("miek.nl"))
	mx.Class(ClassINET)

	msg := new(Msg)
	msg.Opcode(OpcodeQuery)

	q := NewSection(SectionQuestion)
	q.Append(mx)

	t.Logf("%v\n", msg.Octets())
}
