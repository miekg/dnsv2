package dns

import (
	"fmt"
	"os"
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

func TestReadMsgBinary(t *testing.T) {
	buf, _ := os.ReadFile("testdata/dig-mx-miek.nl")
	msg := new(Msg)
	msg.Data = buf
	fmt.Printf("%v\n", buf)
	fmt.Printf("%s\n", msg)
	if err := msg.Unpack(); err != nil {
		t.Fatal(err)
	}
}
