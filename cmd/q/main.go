package main

import (
	"fmt"
	"log"
	"net"

	dns "github.com/miekg/dnsv2"
)

func main() {
	c, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		log.Fatal(err)
	}
	m := dns.NewMsg(make([]byte, 512))
	m.SetID(42)

	a := &dns.A{Header: dns.Header{Name: dns.NewName("example.net."), Class: dns.ClassINET}}
	m.SetRR(dns.Qd, a)

	if _, err := c.Write(m.Buf); err != nil {
		log.Fatal(err)
	}

	if _, err := c.Read(m.Buf); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s", m)
}
