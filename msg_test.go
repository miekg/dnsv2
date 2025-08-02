package dns

import (
	"os"
	"testing"

	"github.com/miekg/dnsv2/dnswire"
)

// Testdata was prepared with tcpdump and wireshark and doing live queries.
// sudo tcpdump -w /tmp/mx.pcap -i wlp1s0f0 port 53
// and "dig mx miek.nl"
// Using wireshark to convert the DNS message into bytes that are saved to a file.

func TestMsgQuestionMX(t *testing.T) {
	// test making a Msg
	mx := new(MX)
	mx.Name(dnswire.Name{}.Marshal("miek.nl"))
	mx.Class(ClassINET)
	t.Logf("%d %v\n", 10, mx.String())

	msg := new(Msg)
	msg.Opcode(OpcodeQuery)
	q := new(Question)
	q.Append(mx)
	t.Logf("%d %v\n", len(q.octets), q.octets)
	msg.Question(q)

	t.Logf("%d %v\n", len(msg.Octets()), msg.Octets())
}

func TestMsgBinary(t *testing.T) {
	// test creating stuff from a Msg
	buf, err := os.ReadFile("testdata/dig-mx-miek.nl")
	if err != nil {
		t.Fatal(err)
	}
	msg := new(Msg)
	msg.Octets(buf)

	a := msg.Answer()
	if a.Len() != 5 {
		t.Fatalf("expected %d RRs in the answer section, got %d", 5, a.Len())
	}
	t.Logf("%d %v\n", len(a.octets), a.octets)
	i := 0
	for range a.RRs() {
		i++
	}
	if i != 5 {
		t.Fatalf("expected %d RRs when range-ing the answer section, got %d", 5, i)
	}
}
