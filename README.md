# Alternative (more granular) approach to a DNS library

> Less is more.

**WORK-IN-PROGRESS**

“All these worlds are yours except Europa. Attempt no landing there.”

Eyeing what a more memory efficient DNS libary would look like, while retaining the ease of use
miekg/dns has. Everything here can, and will, change. If you have opinions open an issue.

DNS compression is always done. Making this optional and a user knob is a mistake.

## Memory Model

A message is the central buffer, extracting RRs and walking the message to get RRs will _copy_ the
data out of the message and into the RR. These new buffers can either be pre-allocated (and will be
resized by this package), or allocated anew. After you got all the data from a message its buffer
can be reused/discarded.

Creating a new message works opposite. Bytes from RRs are copied into the message. Once the message
is fully created the RR's buffer maybe reused/discarded.

## API

As everything in DNS looks like an RR, the choice was made to make everything an RR. Notably the
question section of the DNS message is also an RR (albeit lacking rdata and a TTL), but if you
extract a question "RR" you get an `RR`.

EDNS0's RR: the `OPT` RR's option also mimics the `RR` interface as much as possible. In some sense
the options in the `OPT` record are mini RRs.

It is now possible to access the specific rdata elements from an RR and the default String()
functions now only return the text representation of the rdata. This should give much better options
at storing parts of an RR.

All functions/methods allow you to give (an) optional buffer that you control.

`Msg` is the central struct. It contains the RRs either from the wire or when being build up.
Building a Msg needs to happen in-order, as a DNS message can only be traversed from the start.
The buffer containing the wire data is a public member, so the caller can have complete control.

Reading from a `Msg` can be done via any section in any order, from within a section it needs be
in-order. Writing a `Msg` can only be done in the order: Qd, An, Ns, and Ar, where empty sections
can be skipped.

Methods on a `Msg` are:

* `RR(s Section) RR` which returns the _next_ RR from the section or `nil` when none found. As said
    above there is no different method for the question section.
* `SetRR(s Section, r RR)` will add an RR to the specific section, again the order is important, so first
    question section `Qd`, and then answer `An`, authority `Ns` and lastly additional `Ar`.
* `RRs(s Section) []RR` returns all RRs from a specific section.
* `SetRRs(s Section, rs []RR)` sets an entire section.

### Questionable things

* Doing `[2]byte{x, y}` instead of a uint16 for `Class` and `Type`?
* Needing helper function in the `dnswire` package to convert from an to rdata types.
* `Msg` can only be written in the correct order. Technically we should be able to insert RRs, but
    this requires updating compression pointers which need to be found?
* The `Header` doesn't contain the type, as this is encoded in the Go Type of the RR, so printing
    them as strings looks a bit weird (compared to dig).
* OPT RR's header needs special casing
* Question "RR" needs special casing because it obvs isn't a real RR either.
* Printing a Msg means walking it, so we can't provide a function for it, unless we return the
    parsed RRs?

### TODO

Label manipulation functions still need to be defined, and seeing what other things might be helpful
without bloating the package.

Maybe this should serve as a lower level package, `dnsrr` and build a nicer API on top? I.e should
server and client be here or in a `dnsnet` pkg?
