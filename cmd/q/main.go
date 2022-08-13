package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	dns "github.com/miekg/dnsv2"
)

var (
	flgDump = flag.Bool("d", false, "write echo contents to standard error in a Go byte slice format")
)

func main() {
	flag.Parse()
	if flag.NArg() == 0 {
		log.Fatal("synopsis: q name [TYPE]")
	}

	m := dns.NewMsg(make([]byte, 4096))

	dn := dns.NewName(flag.Arg(0))
	if dn == nil {
		log.Fatalf("%s is not a valid domain name", flag.Arg(0))
	}
	rr := dns.TypeToRR[dns.TypeA]()
	if flag.NArg() == 2 {
		t, ok := dns.StringToType[flag.Arg(1)]
		if !ok {
			log.Fatalf("%s is not a known type", flag.Arg(1))
		}
		rr = dns.TypeToRR[t]()
	}

	// Compose message to ask the question.
	rr.Hdr().Name, rr.Hdr().Class = dn, dns.IN
	m.SetRR(dns.Qd, rr)
	m.SetID()
	m.SetFlag(dns.RD)

	opt := dns.NewOPT()
	opt.SetDo()
	opt.SetSize(4096)

	m.SetRR(dns.Ar, opt)

	println(m.String())
	return

	c, err := net.Dial("udp", "8.8.4.4:53")
	if err != nil {
		log.Fatalf("failed to dial: %s", err)
	}

	c.SetWriteDeadline(time.Now().Add(2 * time.Second))
	n, err := c.Write(m.Buf[:m.Len()])
	if err != nil {
		log.Fatalf("failed to write: %s", err)
	}
	if n != m.Len() {
		log.Fatal("short write")
	}

	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err = c.Read(m.Buf); err != nil {
		log.Fatalf("failed to read: %s", err)
	}
	m.Buf = m.Buf[:n]
	m.Reset()

	if *flgDump {
		dump(m.Buf)
	}

	fmt.Println(m.String())
}

func dump(buf []byte) {
	b := &strings.Builder{}
	b.WriteString("[]byte{")
	for i := range buf {
		if i%8 == 0 {
			b.WriteString("\n\t")
		}
		b.WriteString(fmt.Sprintf("0x%0x, ", buf[i]))
	}
	b.WriteString("\n}\n")
	fmt.Fprint(os.Stderr, b.String())
}
