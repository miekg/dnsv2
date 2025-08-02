package dns

import "github.com/miekg/dnsv2/dnswire"

func (rr *RFC3597) Msg(x ...*Msg) *Msg {
	if len(x) == 0 {
		return rr.msg
	}
	rr.msg = x[0]
	return nil
}

func (rr *RFC3597) Name(x ...dnswire.Name) (dnswire.Name, error) {
	return (&Hdr{rr.octets, rr.msg}).Name(x...)
}

func (rr *RFC3597) Type(x ...dnswire.Type) (dnswire.Type, error) {
	return (&Hdr{rr.octets, rr.msg}).Type(x...)
}

func (rr *RFC3597) Class(x ...dnswire.Class) (dnswire.Class, error) {
	return (&Hdr{rr.octets, rr.msg}).Class(x...)
}

func (rr *RFC3597) TTL(x ...dnswire.TTL) (dnswire.TTL, error) {
	return (&Hdr{rr.octets, rr.msg}).TTL(x...)
}

func (rr *RFC3597) Octets(x ...[]byte) []byte {
	if len(x) == 0 {
		return rr.octets
	}
	rr.octets = x[0]
	return nil
}

func (rr *A) Msg(x ...*Msg) *Msg {
	if len(x) == 0 {
		return rr.msg
	}
	rr.msg = x[0]
	return nil
}

func (rr *A) Name(x ...dnswire.Name) (dnswire.Name, error) {
	return (&Hdr{rr.octets, rr.msg}).Name(x...)
}

func (rr *A) Type(x ...dnswire.Type) (dnswire.Type, error) {
	return (&Hdr{rr.octets, rr.msg}).Type(x...)
}

func (rr *A) Class(x ...dnswire.Class) (dnswire.Class, error) {
	return (&Hdr{rr.octets, rr.msg}).Class(x...)
}
func (rr *A) TTL(x ...dnswire.TTL) (dnswire.TTL, error) { return (&Hdr{rr.octets, rr.msg}).TTL(x...) }

func (rr *A) Octets(x ...[]byte) []byte {
	if len(x) == 0 {
		return rr.octets
	}
	rr.octets = x[0]
	return nil
}

func (rr *MX) Msg(x ...*Msg) *Msg {
	if len(x) == 0 {
		return rr.msg
	}
	rr.msg = x[0]
	return nil
}

func (rr *MX) Name(x ...dnswire.Name) (dnswire.Name, error) {
	return (&Hdr{rr.octets, rr.msg}).Name(x...)
}

func (rr *MX) Type(x ...dnswire.Type) (dnswire.Type, error) {
	return (&Hdr{rr.octets, rr.msg}).Type(x...)
}

func (rr *MX) Class(x ...dnswire.Class) (dnswire.Class, error) {
	return (&Hdr{rr.octets, rr.msg}).Class(x...)
}
func (rr *MX) TTL(x ...dnswire.TTL) (dnswire.TTL, error) { return (&Hdr{rr.octets, rr.msg}).TTL(x...) }

func (rr *MX) Octets(x ...[]byte) []byte {
	if len(x) == 0 {
		return rr.octets
	}
	rr.octets = x[0]
	return nil
}

func (rr *OPT) Msg(x ...*Msg) *Msg {
	if len(x) == 0 {
		return rr.msg
	}
	rr.msg = x[0]
	return nil
}

func (rr *OPT) Name(x ...dnswire.Name) (dnswire.Name, error) {
	return (&Hdr{rr.octets, rr.msg}).Name(x...)
}

func (rr *OPT) Type(x ...dnswire.Type) (dnswire.Type, error) {
	return (&Hdr{rr.octets, rr.msg}).Type(x...)
}

func (rr *OPT) Class(x ...dnswire.Class) (dnswire.Class, error) {
	return (&Hdr{rr.octets, rr.msg}).Class(x...)
}
func (rr *OPT) TTL(x ...dnswire.TTL) (dnswire.TTL, error) { return (&Hdr{rr.octets, rr.msg}).TTL(x...) }

func (rr *OPT) Octets(x ...[]byte) []byte {
	if len(x) == 0 {
		return rr.octets
	}
	rr.octets = x[0]
	return nil
}
