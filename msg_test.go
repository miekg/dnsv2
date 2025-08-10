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
	if err := msg.Unpack(); err != nil {
		fmt.Printf("%s\n", msg)
		t.Fatal(err)
	}
	fmt.Printf("%s\n", msg)
}

func TestUnpackName(t *testing.T) {
	tcs := []struct {
		buf   []byte
		start int
		name  string
		off   int
	}{
		// miek.nl (4 miek 2 nl 0)
		{[]byte{4, 109, 105, 101, 107, 2, 110, 108, 0}, 0, "miek.nl.", 9},
		// beginning of a message, ID (98, 24),... then miek.nl as question = 0 15 (mx as type) and 0 01 as
		// class. But then 192 12 which is a pointer to miek.nl, so lets decode that.
		{[]byte{98, 24, 129, 128, 0, 1, 0, 5, 0, 0, 0, 1, 4, 109, 105, 101, 107, 2, 110, 108, 0, 0, 15, 0, 1, 192, 12, 0}, 25, "miek.nl.", 27},
	}
	for i, tc := range tcs {
		t.Run(fmt.Sprintf("test %d", i), func(t *testing.T) {
			name, off, err := UnpackName(tc.buf, tc.start)
			if err != nil {
				t.Fatal(err)
			}
			if name != tc.name {
				t.Errorf("expected name %s, got %s", tc.name, name)
			}
			if off != tc.off {
				t.Errorf("expected offset %d, got %d", tc.off, off)
			}
		})
	}
}
