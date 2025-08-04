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

More details:

- Question section only holds 1 quesstion.

## When am I happy with the API?

In CoreDNS there is a plugin that takes all the RRs in the answer section and shuffles them (_loadbalance_
plugin). I want to be able to mimic this here, with a nice API and something that is efficient (less copying,
working with wire-data).

## Problems that hamper effiency

If you get a message (with compressed) RR in the additional section and you replace the answer section all
those compression pointers may now be broken.

> To solve this in others like it: we decompress received messages by default. Making those can only be done
> once a Msg is been finished and calling Compress().

## TODO

- finish parsing MX, A and OPT
- edns0 OPT parsing and hacks
- reading/writing dns.Msg
- benchmarking with miekg/dns (mostly)
- fuzzing

once the above is in place and tested (and fuzzed), some bench functions will be written to compare this to
miekg/dns. Then a decision is made to continue or not.
