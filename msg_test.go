package dns

import (
	"testing"
)

// Testdata was prepared with tcpdump and wireshark and doing live queries.
// sudo tcpdump -w /tmp/mx.pcap -i wlp1s0f0 port 53
// and "dig mx miek.nl"
// Using wireshark to convert the DNS message into bytes that are saved to a file.

func TestMakeMsgQuestionMX(t *testing.T) {
	mx := &MX{Header{Name: "miek.nl."}, 10, "mx.miek.nl."}
	println(mx.String())
}
