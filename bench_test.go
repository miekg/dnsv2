package dns

import (
	"testing"

	"github.com/miekg/dnsv2/dnswire"
)

func BenchmarkMakeMsgQuestionMX(b *testing.B) {
	for b.Loop() {
		mx := new(MX)
		mx.Name(dnswire.Name{}.Marshal("miek.nl."))
		mx.Class(ClassINET)

		msg := new(Msg)
		msg.ID(ID())
		q := &Question{Msg: msg}
		q.Append(mx)
	}
}
