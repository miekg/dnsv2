package dns

// Code option codes.
const (
	CodeLLQ          uint16 = 0x1    // Long lived queries: http://tools.ietf.org/html/draft-sekar-dns-llq-01
	CodeUL           uint16 = 0x2    // Update lease draft: http://files.dns-sd.org/draft-sekar-dns-ul.txt
	CodeNSID         uint16 = 0x3    // Nsid (See RFC 5001)
	CodeESU          uint16 = 0x4    // ENUM Source-URI draft: https://datatracker.ietf.org/doc/html/draft-kaplan-enum-source-uri-00
	CodeDAU          uint16 = 0x5    // DNSSEC Algorithm Understood
	CodeDHU          uint16 = 0x6    // DS Hash Understood
	CodeN3U          uint16 = 0x7    // NSEC3 Hash Understood
	CodeSUBNET       uint16 = 0x8    // Client-subnet (See RFC 7871)
	CodeEXPIRE       uint16 = 0x9    // Expire
	CodeCOOKIE       uint16 = 0xa    // Cookie
	CodeTCPKEEPALIVE uint16 = 0xb    // Tcp keep alive (See RFC 7828)
	CodePADDING      uint16 = 0xc    // Padding (See RFC 7830)
	CodeEDE          uint16 = 0xf    // Extended DNS errors (See RFC 8914)
	CodeLOCALSTART   uint16 = 0xFDE9 // Beginning of range reserved for local/experimental use (See RFC 6891)
	CodeLOCALEND     uint16 = 0xFFFE // End of range reserved for local/experimental use (See RFC 6891)
)

// NSID EDNS0 option is used to retrieve a nameserver identifier. When sending a request Nsid must be empty.
// The identifier is an opaque string encoded as hex.
type NSID struct {
	Header
	Nsid string `dns:"hex"`
}

// PADDING option is used to add padding to a request/response. The default value of padding SHOULD be 0x0 but other values MAY be us>
// compression is applied before encryption which may break signatures.
type PADDING struct {
	Header
	Padding string `dns:"octet"`
}
