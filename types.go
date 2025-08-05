package dns

// An RR represents a DNS resource record.
type RR interface {
	// Header returns the header of an resource record.
	Header() Header
	// String returns the text representation of the resource record.
	String() string
	// Data returns all the rdata fields of the resource record.
	Data() []Field
}

// Field is a rdata element in a resource record.
type Field interface {
	// empty interface for now, maybe String()?
}

// Header is the header in a DNS resource record.
type Header struct {
	Name  string `dns:"cdomain-name"`
	Type  uint16 // Type is the type of the RR, normally this is left empty as the type is inferred from the Go type.
	Class uint16 // Class is the class of the RR, this is mostly [ClassINET].
	TTL   uint32 // TTL is the time-to-live of the RR.
	// rdlength is calculated.
}

const (
	MsgHeaderLen = 12 // MsgHeaderLen is the length of the header in the DNS message.
	maxPtrs      = 10 // maxPointers is the maximum number of pointers we will follow when decompressing a DNS name.
)

// EDNS0 determines if the "RR" is posing as an EDNS0 option. EDNS0 options are considered just RRs and must
// be added to the [Pseudo] section of a DNS message.
type EDNS0 interface {
	RR
	Pseudo() bool
}

// MsgHeader is the header of a DNS message. This contains most header bits, except Rcode as that needs to be
// set via a function because of the extended Rcode that lives in the pseudo section.
type MsgHeader struct {
	ID                 uint16
	Response           bool
	Opcode             int8
	Authoritative      bool
	Truncated          bool
	RecursionDesired   bool
	RecursionAvailable bool
	Zero               bool
	AuthenticatedData  bool
	CheckingDisabled   bool
	//	Rcode              int
}

// Msg is a DNS message.
type Msg struct {
	Question RR   // Holds the RR of the question section.
	Answer   []RR // Holds the RR(s) of the answer section.
	Ns       []RR // Holds the RR(s) of the authority section.
	Extra    []RR // Holds the RR(s) of the additional section.
	Pseudo   []RR // Holds the RR(s) of the (virtual) peusdo section.
}

// Wire constants and supported types.
const (
	// valid RR types.
	TypeNone       uint16 = 0
	TypeA          uint16 = 1
	TypeNS         uint16 = 2
	TypeMD         uint16 = 3
	TypeMF         uint16 = 4
	TypeCNAME      uint16 = 5
	TypeSOA        uint16 = 6
	TypeMB         uint16 = 7
	TypeMG         uint16 = 8
	TypeMR         uint16 = 9
	TypeNULL       uint16 = 10
	TypePTR        uint16 = 12
	TypeHINFO      uint16 = 13
	TypeMINFO      uint16 = 14
	TypeMX         uint16 = 15
	TypeTXT        uint16 = 16
	TypeRP         uint16 = 17
	TypeAFSDB      uint16 = 18
	TypeX25        uint16 = 19
	TypeISDN       uint16 = 20
	TypeRT         uint16 = 21
	TypeNSAPPTR    uint16 = 23
	TypeSIG        uint16 = 24
	TypeKEY        uint16 = 25
	TypePX         uint16 = 26
	TypeGPOS       uint16 = 27
	TypeAAAA       uint16 = 28
	TypeLOC        uint16 = 29
	TypeNXT        uint16 = 30
	TypeEID        uint16 = 31
	TypeNIMLOC     uint16 = 32
	TypeSRV        uint16 = 33
	TypeATMA       uint16 = 34
	TypeNAPTR      uint16 = 35
	TypeKX         uint16 = 36
	TypeCERT       uint16 = 37
	TypeDNAME      uint16 = 39
	TypeOPT        uint16 = 41 // EDNS
	TypeAPL        uint16 = 42
	TypeDS         uint16 = 43
	TypeSSHFP      uint16 = 44
	TypeIPSECKEY   uint16 = 45
	TypeRRSIG      uint16 = 46
	TypeNSEC       uint16 = 47
	TypeDNSKEY     uint16 = 48
	TypeDHCID      uint16 = 49
	TypeNSEC3      uint16 = 50
	TypeNSEC3PARAM uint16 = 51
	TypeTLSA       uint16 = 52
	TypeSMIMEA     uint16 = 53
	TypeHIP        uint16 = 55
	TypeNINFO      uint16 = 56
	TypeRKEY       uint16 = 57
	TypeTALINK     uint16 = 58
	TypeCDS        uint16 = 59
	TypeCDNSKEY    uint16 = 60
	TypeOPENPGPKEY uint16 = 61
	TypeCSYNC      uint16 = 62
	TypeZONEMD     uint16 = 63
	TypeSVCB       uint16 = 64
	TypeHTTPS      uint16 = 65
	TypeSPF        uint16 = 99
	TypeUINFO      uint16 = 100
	TypeUID        uint16 = 101
	TypeGID        uint16 = 102
	TypeUNSPEC     uint16 = 103
	TypeNID        uint16 = 104
	TypeL32        uint16 = 105
	TypeL64        uint16 = 106
	TypeLP         uint16 = 107
	TypeEUI48      uint16 = 108
	TypeEUI64      uint16 = 109
	TypeNXNAME     uint16 = 128
	TypeURI        uint16 = 256
	TypeCAA        uint16 = 257
	TypeAVC        uint16 = 258
	TypeAMTRELAY   uint16 = 260
	TypeRESINFO    uint16 = 261

	TypeTKEY uint16 = 249
	TypeTSIG uint16 = 250

	// Valid Question types only.
	TypeIXFR  uint16 = 251
	TypeAXFR  uint16 = 252
	TypeMAILB uint16 = 253
	TypeMAILA uint16 = 254
	TypeANY   uint16 = 255

	TypeTA       uint16 = 32768
	TypeDLV      uint16 = 32769
	TypeReserved uint16 = 65535

	// Valid DNS classes.
	ClassINET   = 1
	ClassCSNET  = 2
	ClassCHAOS  = 3
	ClassHESIOD = 4
	ClassNONE   = 254
	ClassANY    = 255

	// Message Response Codes, see https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
	RcodeSuccess                    = 0  // NoError   - No Error                          [DNS]
	RcodeFormatError                = 1  // FormErr   - Format Error                      [DNS]
	RcodeServerFailure              = 2  // ServFail  - Server Failure                    [DNS]
	RcodeNameError                  = 3  // NXDomain  - Non-Existent Domain               [DNS]
	RcodeNotImplemented             = 4  // NotImp    - Not Implemented                   [DNS]
	RcodeRefused                    = 5  // Refused   - Query Refused                     [DNS]
	RcodeYXDomain                   = 6  // YXDomain  - Name Exists when it should not    [DNS Update]
	RcodeYXRrset                    = 7  // YXRRSet   - RR Set Exists when it should not  [DNS Update]
	RcodeNXRrset                    = 8  // NXRRSet   - RR Set that should exist does not [DNS Update]
	RcodeNotAuth                    = 9  // NotAuth   - Server Not Authoritative for zone [DNS Update]
	RcodeNotZone                    = 10 // NotZone   - Name not contained in zone        [DNS Update/TSIG]
	RcodeStatefulTypeNotImplemented = 11 // DSOTypeNI - DSO-TYPE not implemented          [DNS Stateful Operations] https://www.rfc-editor.org/rfc/rfc8490.html#section-10.2
	RcodeBadSig                     = 16 // BADSIG    - TSIG Signature Failure            [TSIG]  https://www.rfc-editor.org/rfc/rfc6895.html#section-2.3
	RcodeBadVers                    = 16 // BADVERS   - Bad OPT Version                   [EDNS0] https://www.rfc-editor.org/rfc/rfc6895.html#section-2.3
	RcodeBadKey                     = 17 // BADKEY    - Key not recognized                [TSIG]
	RcodeBadTime                    = 18 // BADTIME   - Signature out of time window      [TSIG]
	RcodeBadMode                    = 19 // BADMODE   - Bad TKEY Mode                     [TKEY]
	RcodeBadName                    = 20 // BADNAME   - Duplicate key name                [TKEY]
	RcodeBadAlg                     = 21 // BADALG    - Algorithm not supported           [TKEY]
	RcodeBadTrunc                   = 22 // BADTRUNC  - Bad Truncation                    [TSIG]
	RcodeBadCookie                  = 23 // BADCOOKIE - Bad/missing Server Cookie         [DNS Cookies]

	// Message Opcodes. There is no 3.
	OpcodeQuery    = 0
	OpcodeIQuery   = 1
	OpcodeStatus   = 2
	OpcodeNotify   = 4
	OpcodeUpdate   = 5
	OpcodeStateful = 6
)
