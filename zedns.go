package dns

import "github.com/miekg/dnsv2/dnswire"

func (rr *NSID) Pseudo() bool                                 { return true }
func (rr *NSID) Msg(x ...*Msg) *Msg                           { return nil }
func (rr *NSID) Name(x ...dnswire.Name) (dnswire.Name, error) { return Hdr{rr.octets, nil}.Name(x...) }
func (rr *NSID) Type(x ...dnswire.Type) (dnswire.Type, error) { return Hdr{rr.octets, nil}.Type(x...) }
func (rr *NSID) TTL(x ...dnswire.TTL) (dnswire.TTL, error)    { return Hdr{rr.octets, nil}.TTL(x...) }
func (rr *NSID) Class(x ...dnswire.Class) (dnswire.Class, error) {
	return Hdr{rr.octets, nil}.Class(x...)
}

func (rr *NSID) Octets(x ...[]byte) []byte {
	if len(x) == 0 {
		return rr.octets
	}
	rr.octets = x[0]
	return nil
}

func (rr *PADDING) Pseudo() bool       { return true }
func (rr *PADDING) Msg(x ...*Msg) *Msg { return nil }
func (rr *PADDING) Name(x ...dnswire.Name) (dnswire.Name, error) {
	return Hdr{rr.octets, nil}.Name(x...)
}

func (rr *PADDING) Type(x ...dnswire.Type) (dnswire.Type, error) {
	return Hdr{rr.octets, nil}.Type(x...)
}
func (rr *PADDING) TTL(x ...dnswire.TTL) (dnswire.TTL, error) { return Hdr{rr.octets, nil}.TTL(x...) }
func (rr *PADDING) Class(x ...dnswire.Class) (dnswire.Class, error) {
	return Hdr{rr.octets, nil}.Class(x...)
}

func (rr *PADDING) Octets(x ...[]byte) []byte {
	if len(x) == 0 {
		return rr.octets
	}
	rr.octets = x[0]
	return nil
}
