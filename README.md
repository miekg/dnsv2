# Alternative (more granular) approach to a DNS library

> Less is more.

**WORK-IN-PROGRESS**

“All these worlds are yours except Europa. Attempt no landing there.”

Eyeing what a more memory efficient DNS libary would look like, while retaining the ease of use
miekg/dns has. Everything here can, and will, change. If you have opinions open an issue.

## Memory Model

A message is the central buffer, extracting RRs and walking the message to get RRs will _copy_ the
data out of the message and into the RR. These new buffer can either be pre-allocated (and will be
resized by this package), or allacated anew. After you got all the data from a message its buffer
can be reused/discarded.

Creating a new message works opposite. Bytes from RRs are copied into the message. Once the message
is fully created the RR's buffer maybe reused/discarded.
