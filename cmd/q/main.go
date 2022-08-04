package main

import (
	"fmt"
	"log"
	"net"
	"time"

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
