package dns

import (
	"fmt"
	"os"
	"testing"

	"github.com/miekg/dnsv2/dnswire"
)

// Testdata was prepared with tcpdump and wireshark and doing live queries.
// sudo tcpdump -w /tmp/mx.pcap -i wlp1s0f0 port 53
// and "dig mx miek.nl"
// Using wireshark to convert the DNS message into bytes that are saved to a file.

func TestMakeMsgQuestionMX(t *testing.T) {
	mx := new(MX)
	mx.Name(dnswire.Name{}.Marshal("miek.nl"))
	mx.Class(ClassINET)
	t.Logf("%d %v\n", 10, mx.String())

	msg := new(Msg)
	q := new(Question)
	q.Msg = msg
	q.Append(mx)
	t.Logf("%d %v\n", len(q.octets), q.octets)
	msg.Question(q)

	t.Logf("%d %v\n", len(msg.Octets()), msg.Octets())
}

func TestReadMsgBinary(t *testing.T) {
	buf, _ := os.ReadFile("testdata/dig-mx-miek.nl")
	msg := new(Msg)
	msg.Octets(buf)
	t.Logf("   Msg %d %v\n", len(msg.Octets()), msg.Octets())

	a := msg.Answer()
	t.Logf("Answer %d %v %d %d\n", len(a.Octets()), a.Octets(), a.start, a.end)
	if a.Len() != 5 {
		t.Fatalf("expected %d RRs in the answer section, got %d", 5, a.Len())
	}
	i := 0
	for range a.RRs() {
		i++
	}
	if i != 5 {
		t.Fatalf("expected %d RRs when range-ing the answer section, got %d", 5, i)
	}
	for rr := range a.RRs() {
		fmt.Printf("%v\n", rr.Octets())
		fmt.Println(rr.String())
	}
}
