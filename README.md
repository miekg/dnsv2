# Go DNS library

Principles of design:

- Everything is stored in wire data (boils down to `[]byte`).
- Building a message is down by making RRs and then adding them to the appropriate section.
- Creating a message means copying data _to_ the message.
- Getting data out of a message means copying data _from_ the message.
- Connection handling is completely left out, i.e. no more `dns.Conn`.

With the latter two points, we allow these elements to the self contained (albeit with copying), otherwise you
will get into the situation that an RR that is added to a message can be altered (in sometimes bad way) when
the message is altered (think randomizing the RRs in a section), or just setting the TTLs in a RR which can
then influence the RR that you have in a cache.
