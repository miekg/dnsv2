package dns

import "fmt"

// Error represents a DNS error.
type Error struct {
	Msg string
}

// Errors defined in this package.
var (
	ErrAlg           error = &Error{Msg: "bad algorithm"}          // ErrAlg indicates an error with the (DNSSEC) algorithm.
	ErrAuth          error = &Error{Msg: "bad authentication"}     // ErrAuth indicates an error in the TSIG authentication.
	ErrBuf           error = &Error{Msg: "buffer size too small"}  // ErrBuf indicates that the buffer used is too small for the message.
	ErrConnEmpty     error = &Error{Msg: "conn has no connection"} // ErrConnEmpty indicates a connection is being used before it is initialized.
	ErrExtendedRcode error = &Error{Msg: "bad extended rcode"}
	ErrFqdn          error = &Error{Msg: "domain must be fully qualified"} // ErrFqdn indicates that a domain name does not have a closing dot.
	ErrId            error = &Error{Msg: "id mismatch"}                    // ErrId indicates there is a mismatch with the message's ID.
	ErrKeyAlg        error = &Error{Msg: "bad key algorithm"}              // ErrKeyAlg indicates that the algorithm in the key is not valid.
	ErrKey           error = &Error{Msg: "bad key"}
	ErrKeySize       error = &Error{Msg: "bad key size"}
	ErrLongDomain    error = &Error{Msg: fmt.Sprintf("domain name exceeded %d wire format octets", maxDomainNameWireOctets)}
	ErrNoSig         error = &Error{Msg: "no signature found"}
	ErrPrivKey       error = &Error{Msg: "bad private key"}
	ErrRdata         error = &Error{Msg: "bad rdata"}
	ErrRRset         error = &Error{Msg: "bad rrset"}
	ErrSecret        error = &Error{Msg: "no secrets defined"}
	ErrShortRead     error = &Error{Msg: "short read"}
	ErrSig           error = &Error{Msg: "bad signature"} // ErrSig indicates that a signature can not be cryptographically validated.
	ErrSoa           error = &Error{Msg: "no SOA"}        // ErrSOA indicates that no SOA RR was seen when doing zone transfers.
	ErrTime          error = &Error{Msg: "bad time"}      // ErrTime indicates a timing error in TSIG authentication.
)

func (e *Error) Error() string { return "dns: " + e.Msg }
