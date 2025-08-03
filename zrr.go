package dns

import "github.com/miekg/dnsv2/dnswire"

func (rr *RFC3597) Name(x ...dnswire.Name) (dnswire.Name, error)    { return _Name(rr, x...) }
func (rr *RFC3597) Type(x ...dnswire.Type) (dnswire.Type, error)    { return _Type(rr, x...) }
func (rr *RFC3597) Class(x ...dnswire.Class) (dnswire.Class, error) { return _Class(rr, x...) }
func (rr *RFC3597) TTL(x ...dnswire.TTL) (dnswire.TTL, error)       { return _TTL(rr, x...) }
func (rr *RFC3597) String() string                                  { return _String(rr) }
func (rr *RFC3597) Octets(x ...[]byte) []byte {
	if len(x) == 0 {
		return rr.octets
	}
	rr.octets = x[0]
	return nil
}

func (rr *A) Name(x ...dnswire.Name) (dnswire.Name, error)    { return _Name(rr, x...) }
func (rr *A) Type(x ...dnswire.Type) (dnswire.Type, error)    { return _Type(rr, x...) }
func (rr *A) Class(x ...dnswire.Class) (dnswire.Class, error) { return _Class(rr, x...) }
func (rr *A) TTL(x ...dnswire.TTL) (dnswire.TTL, error)       { return _TTL(rr, x...) }
func (rr *A) String() string                                  { return _String(rr) }
func (rr *A) Octets(x ...[]byte) []byte {
	if len(x) == 0 {
		return rr.octets
	}
	rr.octets = x[0]
	return nil
}

func (rr *MX) Name(x ...dnswire.Name) (dnswire.Name, error)    { return _Name(rr, x...) }
func (rr *MX) Type(x ...dnswire.Type) (dnswire.Type, error)    { return _Type(rr, x...) }
func (rr *MX) Class(x ...dnswire.Class) (dnswire.Class, error) { return _Class(rr, x...) }
func (rr *MX) TTL(x ...dnswire.TTL) (dnswire.TTL, error)       { return _TTL(rr, x...) }
func (rr *MX) String() string                                  { return _String(rr) }
func (rr *MX) Octets(x ...[]byte) []byte {
	if len(x) == 0 {
		return rr.octets
	}
	rr.octets = x[0]
	return nil
}

func (rr *OPT) Name(x ...dnswire.Name) (dnswire.Name, error)    { return _Name(rr, x...) }
func (rr *OPT) Type(x ...dnswire.Type) (dnswire.Type, error)    { return _Type(rr, x...) }
func (rr *OPT) Class(x ...dnswire.Class) (dnswire.Class, error) { return _Class(rr, x...) }
func (rr *OPT) TTL(x ...dnswire.TTL) (dnswire.TTL, error)       { return _TTL(rr, x...) }
func (rr *OPT) String() string                                  { return _String(rr) }
func (rr *OPT) Octets(x ...[]byte) []byte {
	if len(x) == 0 {
		return rr.octets
	}
	rr.octets = x[0]
	return nil
}
