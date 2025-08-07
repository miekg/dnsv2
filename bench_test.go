package dns

import (
	"testing"
)

// BenchmarkCreateMsg benchmarks the creation of a small Msg with a question section only.
func BenchmarkMakeMsgQuestionMX(b *testing.B) {
	for b.Loop() {
		msg := new(Msg)
		msg.ID = ID()
		msg.RecursionDesired = true
		msg.Question = []RR{&MX{Hdr: Header{Name: "miek.nl."}}}
		msg.Pack()
	}
}
