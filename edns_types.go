package dns

import (
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
)

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
	ExtendedErrorOther uint16 = iota
	ExtendedErrorUnsupportedDNSKEYAlgorithm
	ExtendedErrorUnsupportedDSDigestType
	ExtendedErrorStaleAnswer
	ExtendedErrorForgedAnswer
	ExtendedErrorDNSSECIndeterminate
	ExtendedErrorDNSBogus
	ExtendedErrorSignatureExpired
	ExtendedErrorSignatureNotYetValid
	ExtendedErrorDNSKEYMissing
	ExtendedErrorRRSIGsMissing
	ExtendedErrorNoZoneKeyBitSet
	ExtendedErrorNSECMissing
	ExtendedErrorCachedError
	ExtendedErrorNotReady
	ExtendedErrorBlocked
	ExtendedErrorCensored
	ExtendedErrorFiltered
	ExtendedErrorProhibited
	ExtendedErrorStaleNXDOMAINAnswer
	ExtendedErrorNotAuthoritative
	ExtendedErrorNotSupported
	ExtendedErrorNoReachableAuthority
	ExtendedErrorNetworkError
	ExtendedErrorInvalidData
)

// ExtendedErrorToString maps extended error info codes to a human readable description.
var ExtendedErrorToString = map[uint16]string{
	ExtendedErrorOther:                      "Other",
	ExtendedErrorUnsupportedDNSKEYAlgorithm: "Unsupported DNSKEY Algorithm",
	ExtendedErrorUnsupportedDSDigestType:    "Unsupported DS Digest Type",
	ExtendedErrorStaleAnswer:                "Stale Answer",
	ExtendedErrorForgedAnswer:               "Forged Answer",
	ExtendedErrorDNSSECIndeterminate:        "DNSSEC Indeterminate",
	ExtendedErrorDNSBogus:                   "DNSSEC Bogus",
	ExtendedErrorSignatureExpired:           "Signature Expired",
	ExtendedErrorSignatureNotYetValid:       "Signature Not Yet Valid",
	ExtendedErrorDNSKEYMissing:              "DNSKEY Missing",
	ExtendedErrorRRSIGsMissing:              "RRSIGs Missing",
	ExtendedErrorNoZoneKeyBitSet:            "No Zone Key Bit Set",
	ExtendedErrorNSECMissing:                "NSEC Missing",
	ExtendedErrorCachedError:                "Cached Error",
	ExtendedErrorNotReady:                   "Not Ready",
	ExtendedErrorBlocked:                    "Blocked",
	ExtendedErrorCensored:                   "Censored",
	ExtendedErrorFiltered:                   "Filtered",
	ExtendedErrorProhibited:                 "Prohibited",
	ExtendedErrorStaleNXDOMAINAnswer:        "Stale NXDOMAIN Answer",
	ExtendedErrorNotAuthoritative:           "Not Authoritative",
	ExtendedErrorNotSupported:               "Not Supported",
	ExtendedErrorNoReachableAuthority:       "No Reachable Authority",
	ExtendedErrorNetworkError:               "Network Error",
	ExtendedErrorInvalidData:                "Invalid Data",
}

// StringToExtendedError is a map from human readable descriptions to extended error info codes.
var StringToExtendedError = reverseInt16(ExtendedErrorToString)

func unpackOptionCode(option EDNS0, s *cryptobyte.String) error {
	switch x := option.(type) {
	case *NSID:
		return x.unpack(s)
	case *PADDING:
		return x.unpack(s)
	}
	// Coder() check, abuse Type()?
	return fmt.Errorf("no option unpack defined")
}

// NSID EDNS0 option is used to retrieve a nameserver identifier. When sending a request Nsid must be empty.
// The identifier is an opaque string encoded as hex.
type NSID struct {
	Hdr  Header
	Nsid string `dns:"hex"`
}

func (o *NSID) Len() int { return 4 + len(o.Nsid)/2 }
func (o *NSID) String() string {
	sb := sprintOptionHeader(o)
	sb.WriteString(o.Nsid)
	if x, err := hex.DecodeString(o.Nsid); err == nil { // == nil
		sb.WriteString(" ; (\"")
		sb.Write(x)
		sb.WriteByte(')')
	}
	return sb.String()
}

func (o *NSID) unpack(s *cryptobyte.String) error {
	o.Nsid = hex.EncodeToString(*s)
	return nil
}

// PADDING option is used to add padding to a request/response. The default value of padding SHOULD be 0x0 but
// other values MAY be used.
type PADDING struct {
	Hdr     Header
	Padding string `dns:"octet"`
}

func (o *PADDING) Len() int                          { return 0 }
func (o *PADDING) String() string                    { return "" }
func (o *PADDING) unpack(s *cryptobyte.String) error { return nil }
