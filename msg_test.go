package dns

import "testing"

// TestCreateMsg tests the creation of a small Msg with a question section only.
func TestMakeMsgQuestionMX(t *testing.T) {
	msg := new(Msg)
	msg.ID = ID()
	msg.RecursionDesired = true
	msg.Question = []RR{&MX{Hdr: Header{Name: "miek.nl.", Class: ClassINET}}}
	buf, _ := msg.Pack()
	buf = buf
}
