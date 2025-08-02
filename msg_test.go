package dns

import (
	"testing"

	"github.com/miekg/dnsv2/dnswire"
)

func TestMsgQuestionMX(t *testing.T) {
	msg := new(Msg)
	mx := new(MX)
	mx.Name(dnswire.Name("miek.nl."))
	mx.Class(ClassINET)
}
