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
	m.SetRR(dns.Qd, &dns.A{Header: dns.Header{Name: dns.NewName("example.net."), Class: dns.ClassIN}})

	n, err := c.Write(m.Buf[:m.Len()])
	if err != nil {
		log.Fatal(err)
	}
	if n != m.Len() {
		log.Fatal("short write")
	}

	if n, err = c.Read(m.Buf); err != nil {
		log.Fatal(err)
	}
	m.Buf = m.Buf[:n]
	m.Reset()
	fmt.Printf("%s", m)
}
