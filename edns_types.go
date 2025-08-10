package dns

// Code option codes.
const (
	CodeNone         uint16 = 0x0
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

// Extended DNS Error Codes (RFC 8914).
const (
	ExtendedRcodeOther uint16 = iota
	ExtendedRcodeUnsupportedDNSKEYAlgorithm
	ExtendedRcodeUnsupportedDSDigestType
	ExtendedRcodeStaleAnswer
	ExtendedRcodeForgedAnswer
	ExtendedRcodeDNSSECIndeterminate
	ExtendedRcodeDNSBogus
	ExtendedRcodeSignatureExpired
	ExtendedRcodeSignatureNotYetValid
	ExtendedRcodeDNSKEYMissing
	ExtendedRcodeRRSIGsMissing
	ExtendedRcodeNoZoneKeyBitSet
	ExtendedRcodeNSECMissing
	ExtendedRcodeCachedError
	ExtendedRcodeNotReady
	ExtendedRcodeBlocked
	ExtendedRcodeCensored
	ExtendedRcodeFiltered
	ExtendedRcodeProhibited
	ExtendedRcodeStaleNXDOMAINAnswer
	ExtendedRcodeNotAuthoritative
	ExtendedRcodeNotSupported
	ExtendedRcodeNoReachableAuthority
	ExtendedRcodeNetworkError
	ExtendedRcodeInvalidData
)

// ExtendedRcodeToString maps extended error info codes to a human readable description.
var ExtendedRcodeToString = map[uint16]string{
	ExtendedRcodeOther:                      "Other",
	ExtendedRcodeUnsupportedDNSKEYAlgorithm: "Unsupported DNSKEY Algorithm",
	ExtendedRcodeUnsupportedDSDigestType:    "Unsupported DS Digest Type",
	ExtendedRcodeStaleAnswer:                "Stale Answer",
	ExtendedRcodeForgedAnswer:               "Forged Answer",
	ExtendedRcodeDNSSECIndeterminate:        "DNSSEC Indeterminate",
	ExtendedRcodeDNSBogus:                   "DNSSEC Bogus",
	ExtendedRcodeSignatureExpired:           "Signature Expired",
	ExtendedRcodeSignatureNotYetValid:       "Signature Not Yet Valid",
	ExtendedRcodeDNSKEYMissing:              "DNSKEY Missing",
	ExtendedRcodeRRSIGsMissing:              "RRSIGs Missing",
	ExtendedRcodeNoZoneKeyBitSet:            "No Zone Key Bit Set",
	ExtendedRcodeNSECMissing:                "NSEC Missing",
	ExtendedRcodeCachedError:                "Cached Error",
	ExtendedRcodeNotReady:                   "Not Ready",
	ExtendedRcodeBlocked:                    "Blocked",
	ExtendedRcodeCensored:                   "Censored",
	ExtendedRcodeFiltered:                   "Filtered",
	ExtendedRcodeProhibited:                 "Prohibited",
	ExtendedRcodeStaleNXDOMAINAnswer:        "Stale NXDOMAIN Answer",
	ExtendedRcodeNotAuthoritative:           "Not Authoritative",
	ExtendedRcodeNotSupported:               "Not Supported",
	ExtendedRcodeNoReachableAuthority:       "No Reachable Authority",
	ExtendedRcodeNetworkError:               "Network Error",
	ExtendedRcodeInvalidData:                "Invalid Data",
}

// StringToExtendedRcode is a map from human readable descriptions to extended error info codes.
var StringToExtendedRcode = reverseInt16(ExtendedRcodeToString)

// OPT is the EDNS0 RR appended to messages to convey extra (meta) information. See RFC 6891. In messages this
// is found in the pseudo section.
type OPT struct {
	Hdr     Header
	Options []EDNS0 `dns:"opt"`
}

func (rr *OPT) Header() *Header { return &rr.Hdr }
func (rr *OPT) String() string  { return rr.Hdr.String() }

/*
func (rr *OPT) Data() []Field {
	fields := make([]Field, len(rr.Options))
	for i := range rr.Options {
		fields[i] = rr.Options[i]
	}
	return fields
}
*/

func (rr *OPT) Len() int {
	l := rr.Hdr.Len()
	for i := range rr.Options {
		l += rr.Options[i].Len()
	}
	return l
}

var _ RR = &OPT{}

// NSID EDNS0 option is used to retrieve a nameserver identifier. When sending a request Nsid must be empty.
// The identifier is an opaque string encoded as hex.
type NSID struct {
	Hdr  Header
	Nsid string `dns:"hex"`
}

func (rr *NSID) Len() int       { return 0 }
func (rr *NSID) String() string { return "" }

// PADDING option is used to add padding to a request/response. The default value of padding SHOULD be 0x0 but other values MAY be us>
// compression is applied before encryption which may break signatures.
type PADDING struct {
	Hdr     Header
	Padding string `dns:"octet"`
}

func (rr *PADDING) Len() int       { return 0 }
func (rr *PADDING) String() string { return "" }
