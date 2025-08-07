package dns

import "testing"

// BenchmarkCreateMsg benchmarks the creation of a small Msg with a question section only.
func BenchmarkMakeMsgQuestionMX(b *testing.B) {
	for b.Loop() {
		msg := new(Msg)
		msg.Id = Id()
		msg.Compress = true
		msg.RecursionDesired = true
		msg.Question = make([]Question, 1)
		msg.Question[0] = Question{"miek.nl.", TypeMX, ClassINET}
		buf, _ := msg.Pack()
		buf = buf
	}
}
