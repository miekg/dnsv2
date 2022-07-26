# Alternative (more granular) approach to a DNS library

> Less is more.

**WORK-IN-PROGRESS**

“All these worlds are yours except Europa. Attempt no landing there.”

Eyeing what a more memory efficient DNS libary would look like, while retaining the ease of use
miekg/dns has. Everything here can, and will, change. If you have opinions open an issue.

DNS compression is always done. Making this optional and a user knob is a mistake.

## Current Status

* Some very basic RRs are working, the rest is trivial, but some `go generate` would help here.
* EDNS0 is implemented.
* Unknown RRs are implemented.
* Unknown EDNS0 options (not an official thing) are implemented.
* Message creating and parsing works with default compression.

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

RRs in a `Msg` contain compression pointers, anything lifted out of a `Msg` will not contain
compression pointers. I.e. a user should not care about this.

Methods on a `Msg` are:

* `RR(s Section) RR` which returns the _next_ RR from the section or `nil` when none found. As said
    above there is no different method for the question section.
* `SetRR(s Section, r RR)` will add an RR to the specific section, again the order is important, so first
    question section `Qd`, and then answer `An`, authority `Ns` and lastly additional `Ar`.
* `RRs(s Section) []RR` returns all RRs from a specific section.
* `SetRRs(s Section, rs []RR)` sets an entire section.

All RR types are in upper-case, except 'Unknown' as that is the odd one out. UnknownEDNS0 also exist.

All public APIs use `int`, internally most things are `uint16`.

### Examples

#### Stripping OPT RR and Forwarding Message

Take for example a "forwarder", or "resolver", such software takes in coming request and resolves
it, then returns the response. One of the first steps undertaking by it is checking what kind of
EDNS0 option are set. This means finding the OPT RR in the additional section, which should be (in
case of TSIG it might not be) the last RR in the message. Then that (or those) RR(s) need to be
stripped as EDNS0 (and TSIG) are hop-by-hop. And after that a new OPT RR will be added and the
message will be forwarded (with a new message ID). In this use-case it would be nice to re-use as
much of the buffer we already have. The following API is implemented for this:

~~~ go
pos := 0
err := m.Walk(WalkBackward, func(s Section, rr RR, i int) error {
    if s == Ar && RRToType(rr) == TypeOPT {
        pos = i
        return errors.New("found opt RR")
    }
    return nil
})
if err != nil {
    rrs, err := m.Strip(pos + 1)
    opt := rrs[0]
}
~~~

### Questionable things

* Doing `[2]byte{x, y}` instead of a uint16 for `Class` and `Type`?
* Needing helper function in the `dnswire` package to convert from an to rdata types.
* `Msg` can only be written in the correct order. Technically we should be able to insert RRs, but
    this requires updating compression pointers which need to be found?
* The `Header` doesn't contain the type, as this is encoded in the Go Type of the RR, so printing
    them as strings looks a bit weird (compared to dig).
* Question "RR" needs special casing because it obvs isn't a real RR either.
* Len() for RRs and Len() for Options do different things...

### TODO

* From string conversion, also need for scanning zone files.

* Unprintables escaping \DDD in text and domain names.

* TCP writes, with message length - how to optimize and don't have 2 syscalls?
    Leave to user? append(len, oldbuf)

* Label manipulation functions still need to be defined, and seeing what other things might be helpful
    without bloating the package. Name.Next() is a first of these.

* Maybe this should serve as a lower level package, `dnsrr` and build a nicer API on top? I.e should
    server and client be here or in a `dnsnet` pkg?

* Decide where to use `int` and where to use `uint16`. Uint16 is more natural as length and index
    thingy, but `int` is more used in std go stuff (ie. `len` returns an int).

* Length check on domain names (<256) octect, 63 label length.

* Buffer length checks when unpacking and packing.

* Use Octets as a name every where instead of bytes - give that old school feel?

* Make Header also implement the RR interface, so it's also an RR? This would simplify the Msg
    creation, as you can just take a Bytes() from the header as well. Bytes is a bad name.

* Make RRSet a first class citizen, i.e get those from a message, mem friendly struct?

* Implement compression for CNAME, MX, NS, PTR, and SOA.

* unpackXXXX need to take uint16, instead of int.

* strconv.Name, and strconv.IPv4 etc? Should we add these? strconv.Type(t string) Type ??

* [2]byte everywhere is annoying, might change to uin16, uint32, but 48 bits are (TSIG) are crap
    again...
