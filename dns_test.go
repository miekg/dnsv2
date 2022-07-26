package dns

import (
	"fmt"
	"strings"
	"testing"
)

// miek.nl. IN MX request and reply. Both contains OPT RR as well.
// both are compressed.
var (
	query = []byte{
		0xe9, 0x71, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01, 0x04, 0x6d, 0x69, 0x65,
		0x6b, 0x02, 0x6e, 0x6c, 0x00, 0x00, 0x0f, 0x00,
		0x01, 0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x0c, 0x00, 0x0a, 0x00, 0x08,
		0x71, 0xa1, 0xd7, 0x18, 0x60, 0xe4, 0x4d, 0x06,
	}
	reply = []byte{
		0xe9, 0x71, 0x81, 0xa0, 0x00, 0x01, 0x00, 0x05,
		0x00, 0x00, 0x00, 0x01, 0x04, 0x6d, 0x69, 0x65,
		0x6b, 0x02, 0x6e, 0x6c, 0x00, 0x00, 0x0f, 0x00,
		0x01, 0xc0, 0x0c, 0x00, 0x0f, 0x00, 0x01, 0x00,
		0x00, 0x03, 0x84, 0x00, 0x1b, 0x00, 0x05, 0x04,
		0x61, 0x6c, 0x74, 0x32, 0x05, 0x61, 0x73, 0x70,
		0x6d, 0x78, 0x01, 0x6c, 0x06, 0x67, 0x6f, 0x6f,
		0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
		0xc0, 0x0c, 0x00, 0x0f, 0x00, 0x01, 0x00, 0x00,
		0x03, 0x84, 0x00, 0x04, 0x00, 0x01, 0xc0, 0x2c,
		0xc0, 0x0c, 0x00, 0x0f, 0x00, 0x01, 0x00, 0x00,
		0x03, 0x84, 0x00, 0x16, 0x00, 0x0a, 0x06, 0x61,
		0x73, 0x70, 0x6d, 0x78, 0x32, 0x0a, 0x67, 0x6f,
		0x6f, 0x67, 0x6c, 0x65, 0x6d, 0x61, 0x69, 0x6c,
		0xc0, 0x3b, 0xc0, 0x0c, 0x00, 0x0f, 0x00, 0x01,
		0x00, 0x00, 0x03, 0x84, 0x00, 0x0b, 0x00, 0x0a,
		0x06, 0x61, 0x73, 0x70, 0x6d, 0x78, 0x33, 0xc0,
		0x65, 0xc0, 0x0c, 0x00, 0x0f, 0x00, 0x01, 0x00,
		0x00, 0x03, 0x84, 0x00, 0x09, 0x00, 0x05, 0x04,
		0x61, 0x6c, 0x74, 0x31, 0xc0, 0x2c, 0x00, 0x00,
		0x29, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00,
	}
	www = []byte{0x8d, 0x1d, 0x81, 0xa0, 0x00, 0x01, 0x00, 0x02,
		0x00, 0x00, 0x00, 0x01, 0x03, 0x77, 0x77, 0x77,
		0x04, 0x6d, 0x69, 0x65, 0x6b, 0x02, 0x6e, 0x6c,
		0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00,
		0x05, 0x00, 0x01, 0x00, 0x00, 0x02, 0x8c, 0x00,
		0x04, 0x01, 0x61, 0xc0, 0x10, 0xc0, 0x29, 0x00,
		0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x8c, 0x00,
		0x04, 0xb0, 0x3a, 0x77, 0x36, 0x00, 0x00, 0x29,
		0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
)

func tmpbuf(buf []byte) []byte {
	tmpbuf := make([]byte, len(buf))
	copy(tmpbuf, buf)
	return tmpbuf
}

func ExampleMsg_RRs() {
	m := &Msg{Buf: tmpbuf(reply)}

	answer, err := m.RRs(An)
	if err != nil {
		return
	}
	for _, rr := range answer {
		fmt.Printf("%s %s\n", rr.Hdr(), rr)
	}
	// Output: miek.nl. 	  900 IN MX	5 alt2.aspmx.l.google.com.
	// miek.nl. 	  900 IN MX	1 aspmx.l.google.com.
	// miek.nl. 	  900 IN MX	10 aspmx2.googlemail.com.
	// miek.nl. 	  900 IN MX	10 aspmx3.googlemail.com.
	// miek.nl. 	  900 IN MX	5 alt1.aspmx.l.google.com.
}

func ExampleMsg_String() {
	m := &Msg{Buf: tmpbuf(reply)}

	fmt.Printf("%s\n", m)
	/*
	   Ouput: ;; MESSAGE HEADER: opcode: QUERY, status: NOERROR, id: 59761
	   ;; flags: qr rd ra ad; QUESTION 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 1
	   ;; QUESTION SECTION:
	   miek.nl. IN MX

	   ;; ANSWER SECTION:
	   miek.nl. 	  900 IN	MX	5 alt2.aspmx.l.google.com.
	   miek.nl. 	  900 IN	MX	1 aspmx.l.google.com.
	   miek.nl. 	  900 IN	MX	10 aspmx2.googlemail.com.
	   miek.nl. 	  900 IN	MX	10 aspmx3.googlemail.com.
	   miek.nl. 	  900 IN	MX	5 alt1.aspmx.l.google.com.

	   ;; ADDITIONAL SECTION:
	   ;; EDNS: version: 0, flags:; udp: 512
	*/
}

func TestMsgString(t *testing.T) {
	buf := []byte{114, 9, 129, 128, 0, 1, 0, 1, 0, 0, 0, 0, 7, 101, 120, 97, 109, 112, 108, 101, 3, 110, 101, 116, 0, 0, 1, 0, 1, 192, 12, 0, 1, 0, 1, 0, 0, 83, 180, 0, 4, 93, 184, 216, 34}
	m := &Msg{Buf: buf}

	// Had off-by-one error that messed up overflow check, resulting in answer not being printed.
	if !strings.HasSuffix(m.String(), ";; ANSWER SECTION:\nexample.net. 	 21428 IN	A	93.184.216.34\n") {
		t.Fatal("expected message to have ANSWER section with A record, got none")
	}
}
