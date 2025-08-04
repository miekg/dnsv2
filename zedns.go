package dns

import "github.com/miekg/dnsv2/dnswire"

func (rr *NSID) Pseudo() bool                                    { return true }
func (rr *NSID) Name(x ...dnswire.Name) (dnswire.Name, error)    { return _Name(rr, x...) }
func (rr *NSID) Type(x ...dnswire.Type) (dnswire.Type, error)    { return _Type(rr, x...) }
func (rr *NSID) DataLen(x ...uint16) (uint16, error)             { return _DataLen(rr, x...) }
func (rr *NSID) Class(x ...dnswire.Class) (dnswire.Class, error) { return _Class(rr, x...) }
func (rr *NSID) TTL(x ...dnswire.TTL) (dnswire.TTL, error)       { return _TTL(rr, x...) }
func (rr *NSID) String() string                                  { return _String(rr) }
func (rr *NSID) Len() int                                        { return _Len(rr) }
func (rr *NSID) Octets(x ...[]byte) []byte {
	if len(x) == 0 {
		return rr.octets
	}
	rr.octets = x[0]
	return nil
}

func (rr *PADDING) Pseudo() bool                                    { return true }
func (rr *PADDING) Name(x ...dnswire.Name) (dnswire.Name, error)    { return _Name(rr, x...) }
func (rr *PADDING) Type(x ...dnswire.Type) (dnswire.Type, error)    { return _Type(rr, x...) }
func (rr *PADDING) DataLen(x ...uint16) (uint16, error)             { return _DataLen(rr, x...) }
func (rr *PADDING) Class(x ...dnswire.Class) (dnswire.Class, error) { return _Class(rr, x...) }
func (rr *PADDING) TTL(x ...dnswire.TTL) (dnswire.TTL, error)       { return _TTL(rr, x...) }
func (rr *PADDING) String() string                                  { return _String(rr) }
func (rr *PADDING) Len() int                                        { return _Len(rr) } // wrong!
func (rr *PADDING) Octets(x ...[]byte) []byte {
	if len(x) == 0 {
		return rr.octets
	}
	rr.octets = x[0]
	return nil
}
