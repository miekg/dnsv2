package dns

import (
	"context"
	"fmt"
	"testing"
)

func TestClient(t *testing.T) {
	m := &Msg{MsgHeader: MsgHeader{ID: ID(), RecursionDesired: true}}
	mx := &MX{Hdr: Header{Name: "miek.nl.", Class: ClassINET}}
	m.Question = []RR{mx}

	m.Pack()
	c := &Client{}

	r, _, err := c.Exchange(context.Background(), m, "udp", "8.8.8.8:53")
	if err != nil {
		t.Errorf("%s", err)
	}
	fmt.Println(r.String())
}
