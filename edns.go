package dns

// NSID EDNS0 option is used to retrieve a nameserver identifier. When sending a request Nsid must be empty.
// The identifier is an opaque string encoded as hex.
type NSID struct {
	Header
	Nsid string `dns:"hex"`
}

// PADDING option is used to add padding to a request/response. The default value of padding SHOULD be 0x0 but other values MAY be used, for instance if
// compression is applied before encryption which may break signatures.
type PADDING struct {
	Header
	Padding []byte
}
