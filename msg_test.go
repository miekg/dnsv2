package dns

import (
	"fmt"
	"testing"
)

// TestMakeMsgQuestionMX tests the creation of a small Msg with a question section only.
func TestMakeMsgQuestionMX(t *testing.T) {
	msg := &Msg{MsgHeader: MsgHeader{ID: ID(), RecursionDesired: true}}
	mx := &MX{Hdr: Header{Name: "miek.nl.", Class: ClassINET}}
	msg.Question = []RR{mx}
	msg.Pack()
	fmt.Printf("%v\n", msg.Data)
	fmt.Printf("%s\n", msg)
}
