package dns

import (
	"testing"

	"github.com/miekg/dnsv2/dnswire"
)

func TestMX(t *testing.T) {
	// convert to tabel based test later.
	mx := new(MX)
	mx.Name(dnswire.Name{}.Marshal("example.org"))
	mx.Class(ClassINET)
	mx.TTL(400)
	mx.Prio(10)
	mx.Mx(dnswire.Name{}.Marshal("mx.example.org."))

	exp := "example.org.\t400\tIN\tMX\t10 mx.example.org."
	if x := mx.String(); x != exp {
		t.Errorf("expected stringified MX %q, got %q", exp, x)
	}
	t.Log(mx.String())
}
