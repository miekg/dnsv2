# Go DNS library

Current feel of the API can be seen in [msg_test.go](https://github.com/miekg/dnsv2/blob/main/msg_test.go)

Principles of design:

- Everything is stored in decompressed wire data (boils down to `[]byte`).
- Everything is an RR. Question section? Holds an RR. EDNS0 options? RRs. Simplifies the API, because no
  special handling required by the user.
- Connection handling is completely left out, i.e. no more `dns.Conn`, we'll just depend on the `net` package
  to `Dial` for us.
- Building a message is done by making a DNS message (\*Msg), adding a section and then adding the appropriate RRs.
- Creating a message means copying data _to_ the message.
- Getting data out of a message means copying data _from_ the message.

With the latter two points, we allow these elements to be self contained (albeit with copying), otherwise you
will get into the situation that an RR that is added to a message can be altered (in sometimes bad ways) when
the message is altered (think randomizing the RRs in a section), or just setting the TTLs in a RR which can
then influence the RR that you have in a cache.

This library decompresses (resolves all compression pointers) when receiving a message (Msg.Decompress function).

## When am I happy with the API?

In CoreDNS there is a plugin that takes all the RRs in the answer section and shuffles them (_loadbalance_
plugin). I want to be able to mimic this here, with a nice API and something that is efficient (less copying,
working with wire-data).

## TODO

- finish parsing (MX), A and OPT
- edns0 OPT parsing and hacks
- reading/writing dns.Msg
- benchmarking with miekg/dns (mostly), creating and parsing messages? Or full blown server and client - needs
  way more infra in this pkg...
- fuzzing, added one in msg_test.go

once the above is in place and tested (and fuzzed), some bench functions will be written to compare this to
miekg/dns. Then a decision is made to continue or not.

## Sketches/Ideas

Pondering this (eveyrthing is an RR) as the Msg (dig-like) text output.

```
;; QUERY, status: NOERROR, id: 47532
;; flags: qr rd ra ad
;; PSEUDO: 2, QUERY: 1, ANSWER: 5, AUTHORITY: 2, ADDITIONAL: 0

;; PSEUDO SECTION:
;; version: 0, udp: 4096, flags: do
.           0   CLASS0   NSID   "gpdns-ams"

;; QUESTION SECTION:
miek.nl     0   IN  MX  0 .

;; ANSWER SECTION:
miek.nl.    21600   IN      MX      10 aspmx3.googlemail.com.
miek.nl.    21600   IN      MX      5 alt2.aspmx.l.google.com.
miek.nl.    21600   IN      MX      1 aspmx.l.google.com.
miek.nl.    21600   IN      MX      10 aspmx2.googlemail.com.
miek.nl.    21600   IN      MX      5 alt1.aspmx.l.google.com.

;; MSG SIZE: 290
```
