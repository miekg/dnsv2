package dns

import (
	"fmt"
	"testing"
)

// TestMakeMsgQuestionMX tests the creation of a small Msg with a question section only.
func TestMakeMsgQuestionMX(t *testing.T) {
	msg := new(Msg)
	msg.ID = ID()
	msg.RecursionDesired = true
	msg.Question = []RR{&MX{Hdr: Header{Name: "miek.nl."}}}
	msg.Pack()
	fmt.Printf("%v\n", msg.Data)
}
