package dns

import (
	"log"
	"testing"

	"github.com/miekg/dnsv2/dnswire"
)

func TestMsgQuestionMX(t *testing.T) {
	mx := new(MX)
	_, err := mx.Name(dnswire.Name{}.Marshal("miek.nl"))
	if err != nil {
		log.Fatal(err)
	}
	println("CLASS")
	_, err = mx.Class(ClassINET)
	if err != nil {
		log.Fatal(err)
	}
	/*


		msg := new(Msg)
		msg.Opcode(OpcodeQuery)

			q := NewSection(Question)
			q.Append(mx)

			t.Logf("%v\n", msg.Octets())
	*/
}
