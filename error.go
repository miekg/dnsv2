package dns

import "fmt"

// Error represents a DNS error.
type Error struct {
	Err string
}

// Errors defined in this package.
var (
	ErrAlg              = &Error{Err: "bad algorithm"}          // ErrAlg indicates an error with the (DNSSEC) algorithm.
	ErrAuth             = &Error{Err: "bad authentication"}     // ErrAuth indicates an error in the TSIG authentication.
	ErrBuf              = &Error{Err: "buffer size too small"}  // ErrBuf indicates that the buffer used is too small for the message.
	ErrConnEmpty        = &Error{Err: "conn has no connection"} // ErrConnEmpty indicates a connection is being used before it is initialized.
	ErrExtendedRcode    = &Error{Err: "bad extended rcode"}
	ErrFqdn             = &Error{Err: "domain must be fully qualified"} // ErrFqdn indicates that a domain name does not have a closing dot.
	ErrName             = &Error{Err: "bad name"}                       // ErrName indicates a malformed name.
	ErrLabel            = &Error{Err: "bad label"}                      // ErrName indicates a malformed label.
	ErrId               = &Error{Err: "id mismatch"}                    // ErrId indicates there is a mismatch with the message's ID.
	ErrKeyAlg           = &Error{Err: "bad key algorithm"}              // ErrKeyAlg indicates that the algorithm in the key is not valid.
	ErrKey              = &Error{Err: "bad key"}
	ErrKeySize          = &Error{Err: "bad key size"}
	ErrLongName         = &Error{Err: fmt.Sprintf("name exceeded %d wire format octets", maxDomainNameWireOctets)}
	ErrNoSig            = &Error{Err: "no signature found"}
	ErrPrivKey          = &Error{Err: "bad private key"}
	ErrRRset            = &Error{Err: "bad rrset"}
	ErrSecret           = &Error{Err: "no secrets defined"}
	ErrShortRead        = &Error{Err: "short read"}
	ErrSig              = &Error{Err: "bad signature"} // ErrSig indicates that a signature can not be cryptographically validated.
	ErrSoa              = &Error{Err: "no SOA"}        // ErrSOA indicates that no SOA RR was seen when doing zone transfers.
	ErrTime             = &Error{Err: "bad time"}      // ErrTime indicates a timing error in TSIG authentication.
	ErrTruncatedMessage = &Error{Err: "overflow unpacking truncated message"}
	ErrUnpackOverflow   = &Error{Err: "overflow unpacking data"}
	ErrTrailingRData    = &Error{Err: "trailing record rdata"}
)

func (e *Error) Error() string { return "dns: " + e.Err }
