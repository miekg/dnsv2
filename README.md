# Go DNS library

Principles of design:

- Everything is stored in uncompressed wire data (boils down to `[]byte`).
- Connection handling is completely left out, i.e. no more `dns.Conn`, we'll just depend on the `net` pkg.
- Building a message is done by making a DNS message (\*Msg), adding a section and then adding the appropriate RRs.
- Creating a message means copying data _to_ the message.
- Getting data out of a message means copying data _from_ the message.

With the latter two points, we allow these elements to be self contained (albeit with copying), otherwise you
will get into the situation that an RR that is added to a message can be altered (in sometimes bad ways) when
the message is altered (think randomizing the RRs in a section), or just setting the TTLs in a RR which can
then influence the RR that you have in a cache.

This library uncompresses (resolves all compression pointers) when receiving a message (Uncompress function).

## When am I happy with the API?

In CoreDNS there is a plugin that takes all the RRs in the answer section and shuffles them (_loadbalance_
plugin). I want to be able to mimic this here, with a nice API and something that is efficient (less copying,
working with wire-data).

## Problems that hamper effiency

If you get a message (with compressed) RR in the additional section and you replace the answer section all
those compression pointers may now be broken.

## TODO

- finish parsing MX, A and OPT
- edns0 OPT parsing and hacks
- reading/writing dns.Msg

once the above is in place and tested (and fuzzed), some bench functions will be written to compare this to
miekg/dns. Then a decision is made to continue or not.
