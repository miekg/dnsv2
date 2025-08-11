package dns

import "fmt"

// Error represents a DNS error.
type Error struct{ err string }

func (e *Error) Error() string { return "dns: " + e.err }

var (
	ErrAlg              = &Error{err: "bad algorithm"}          // ErrAlg indicates an error with the (DNSSEC) algorithm.
	ErrAuth             = &Error{err: "bad authentication"}     // ErrAuth indicates an error in the TSIG authentication.
	ErrBuf              = &Error{err: "buffer size too small"}  // ErrBuf indicates that the buffer used is too small for the message.
	ErrConnEmpty        = &Error{err: "conn has no connection"} // ErrConnEmpty indicates a connection is being used before it is initialized.
	ErrExtendedRcode    = &Error{err: "bad extended rcode"}
	ErrFqdn             = &Error{err: "domain must be fully qualified"} // ErrFqdn indicates that a domain name does not have a closing dot.
	ErrName             = &Error{err: "bad domain name"}
	ErrLabel            = &Error{err: "bad label type"}
	ErrId               = &Error{err: "id mismatch"}       // ErrId indicates there is a mismatch with the message's ID.
	ErrKeyAlg           = &Error{err: "bad key algorithm"} // ErrKeyAlg indicates that the algorithm in the key is not valid.
	ErrKey              = &Error{err: "bad key"}
	ErrKeySize          = &Error{err: "bad key size"}
	ErrLongDomain       = &Error{err: fmt.Sprintf("domain name exceeded %d wire-format octets", maxDomainNameWireOctets)}
	ErrNoSig            = &Error{err: "no signature found"}
	ErrPrivKey          = &Error{err: "bad private key"}
	ErrRcode            = &Error{err: "bad rcode"}
	ErrRRset            = &Error{err: "bad rrset"}
	ErrSecret           = &Error{err: "no secrets defined"}
	ErrShortRead        = &Error{err: "short read"}
	ErrSig              = &Error{err: "bad signature"} // ErrSig indicates that a signature can not be cryptographically validated.
	ErrSoa              = &Error{err: "no SOA"}        // ErrSOA indicates that no SOA RR was seen when doing zone transfers.
	ErrOpt              = &Error{err: "unknown OPT code"}
	ErrTime             = &Error{err: "bad time"} // ErrTime indicates a timing error in TSIG authentication.
	ErrTruncatedMessage = &Error{err: "overflow unpacking truncated message"}
	ErrUnpackOverflow   = &Error{err: "overflow unpacking data"}
	ErrTrailingRData    = &Error{err: "trailing record rdata"}
	ErrLenRData         = &Error{err: "inconsitent rdata length"}
)
