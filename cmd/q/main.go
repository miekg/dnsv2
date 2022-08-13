package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"time"

	dns "github.com/miekg/dnsv2"
)

func main() {
	flag.Parse()
	if flag.NArg() == 0 {
		log.Fatal("synopsis: q name [TYPE]")
	}

	m := dns.NewMsg(make([]byte, 512))

	dn := dns.NewName(flag.Arg(0))
	if dn == nil {
		log.Fatalf("%s is not a valid domain name", flag.Arg(0))
	}
	var rr dns.RR
	if flag.NArg() == 2 {
		t, ok := dns.StringToType[flag.Arg(1)]
		if !ok {
			log.Fatalf("%s is not a known type", flag.Arg(1))
		}
		rr = dns.TypeToRR[t]()
	}

	rr.Hdr().Name, rr.Hdr().Class = dn, dns.IN
	m.SetRR(dns.Qd, rr)
	m.SetID()
	m.SetFlag(dns.RD)

	c, err := net.Dial("udp", "8.8.4.4:53")
	if err != nil {
		log.Fatal(err)
	}

	c.SetWriteDeadline(time.Now().Add(2 * time.Second))
	n, err := c.Write(m.Buf[:m.Len()])
	if err != nil {
		log.Fatal(err)
	}
	if n != m.Len() {
		log.Fatal("short write")
	}

	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err = c.Read(m.Buf); err != nil {
		log.Fatal(err)
	}
	m.Buf = m.Buf[:n]
	m.Reset()
	fmt.Printf("%s", m)
}
