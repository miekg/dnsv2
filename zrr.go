package dns

import (
	"encoding/binary"
	"strings"

	"github.com/miekg/dnsv2/dnswire"
)

func (rr *RFC3597) Name(x ...dnswire.Name) (dnswire.Name, error)    { return _Name(rr, x...) }
func (rr *RFC3597) Type(x ...dnswire.Type) (dnswire.Type, error)    { return _Type(rr, x...) }
func (rr *RFC3597) DataLen(x ...uint16) (uint16, error)             { return _DataLen(rr, x...) }
func (rr *RFC3597) Class(x ...dnswire.Class) (dnswire.Class, error) { return _Class(rr, x...) }
func (rr *RFC3597) TTL(x ...dnswire.TTL) (dnswire.TTL, error)       { return _TTL(rr, x...) }
func (rr *RFC3597) String() string                                  { return _String(rr) }
func (rr *RFC3597) Len() int                                        { return _Len(rr) }
func (rr *RFC3597) Octets(x ...[]byte) []byte {
	if len(x) == 0 {
		return rr.octets
	}
	rr.octets = x[0]
	return nil
}

func (rr *A) Name(x ...dnswire.Name) (dnswire.Name, error)    { return _Name(rr, x...) }
func (rr *A) Type(x ...dnswire.Type) (dnswire.Type, error)    { return _Type(rr, x...) }
func (rr *A) DataLen(x ...uint16) (uint16, error)             { return _DataLen(rr, x...) }
func (rr *A) Class(x ...dnswire.Class) (dnswire.Class, error) { return _Class(rr, x...) }
func (rr *A) TTL(x ...dnswire.TTL) (dnswire.TTL, error)       { return _TTL(rr, x...) }
func (rr *A) String() string                                  { return _String(rr) }
func (rr *A) Len() int                                        { return _Len(rr) }
func (rr *A) Octets(x ...[]byte) []byte {
	if len(x) == 0 {
		return rr.octets
	}
	rr.octets = x[0]
	return nil
}

func (rr *AAAA) Name(x ...dnswire.Name) (dnswire.Name, error)    { return _Name(rr, x...) }
func (rr *AAAA) Type(x ...dnswire.Type) (dnswire.Type, error)    { return _Type(rr, x...) }
func (rr *AAAA) DataLen(x ...uint16) (uint16, error)             { return _DataLen(rr, x...) }
func (rr *AAAA) Class(x ...dnswire.Class) (dnswire.Class, error) { return _Class(rr, x...) }
func (rr *AAAA) TTL(x ...dnswire.TTL) (dnswire.TTL, error)       { return _TTL(rr, x...) }
func (rr *AAAA) String() string                                  { return _String(rr) }
func (rr *AAAA) Len() int                                        { return _Len(rr) }
func (rr *AAAA) Octets(x ...[]byte) []byte {
	if len(x) == 0 {
		return rr.octets
	}
	rr.octets = x[0]
	return nil
}

func (rr *NS) Name(x ...dnswire.Name) (dnswire.Name, error)    { return _Name(rr, x...) }
func (rr *NS) Type(x ...dnswire.Type) (dnswire.Type, error)    { return _Type(rr, x...) }
func (rr *NS) DataLen(x ...uint16) (uint16, error)             { return _DataLen(rr, x...) }
func (rr *NS) Class(x ...dnswire.Class) (dnswire.Class, error) { return _Class(rr, x...) }
func (rr *NS) TTL(x ...dnswire.TTL) (dnswire.TTL, error)       { return _TTL(rr, x...) }
func (rr *NS) Len() int                                        { return _Len(rr) }
func (rr *NS) String() string                                  { return _String(rr) }
func (rr *NS) Octets(x ...[]byte) []byte {
	if len(x) == 0 {
		return rr.octets
	}
	rr.octets = x[0]
	return nil
}

func (rr *MX) Name(x ...dnswire.Name) (dnswire.Name, error)    { return _Name(rr, x...) }
func (rr *MX) Type(x ...dnswire.Type) (dnswire.Type, error)    { return _Type(rr, x...) }
func (rr *MX) DataLen(x ...uint16) (uint16, error)             { return _DataLen(rr, x...) }
func (rr *MX) Class(x ...dnswire.Class) (dnswire.Class, error) { return _Class(rr, x...) }
func (rr *MX) TTL(x ...dnswire.TTL) (dnswire.TTL, error)       { return _TTL(rr, x...) }
func (rr *MX) Len() int                                        { return _Len(rr) }
func (rr *MX) String() string                                  { return format(_String(rr), rr.Prio().String(), rr.Mx().String()) }
func (rr *MX) Octets(x ...[]byte) []byte {
	if len(x) == 0 {
		return rr.octets
	}
	rr.octets = x[0]
	return nil
}

func (rr *MX) Prio(x ...dnswire.Uint16) dnswire.Uint16 {
	rdlen, err := rr.DataLen()
	if err != nil {
		return 0
	}

	off := rr.Len()
	if rdlen < 2 { // if too short update the rdlength
		rr.octets = append(rr.octets, make([]byte, 2)...)
		rr.DataLen(2)
	}

	if len(x) == 0 {
		i := binary.BigEndian.Uint16(rr.Octets()[off:])
		return dnswire.Uint16(i)
	}
	binary.BigEndian.PutUint16(rr.Octets()[off:], uint16(x[0]))
	return 0
}

func (rr *MX) Mx(x ...dnswire.Name) dnswire.Name {
	rdlen, err := rr.DataLen()
	if err != nil {
		return nil
	}

	off := rr.Len()
	off += 2 // Skip Prio (2 octets)

	if len(x) == 0 {
		return dnswire.Name(rr.Octets()[off:])
	}

	rr.octets = append(rr.octets, x[0]...)
	rdlen += uint16(len(x[0]))
	rr.DataLen(rdlen)
	return nil
}

func (rr *OPT) Name(x ...dnswire.Name) (dnswire.Name, error)    { return _Name(rr, x...) }
func (rr *OPT) Type(x ...dnswire.Type) (dnswire.Type, error)    { return _Type(rr, x...) }
func (rr *OPT) Class(x ...dnswire.Class) (dnswire.Class, error) { return _Class(rr, x...) }
func (rr *OPT) DataLen(x ...uint16) (uint16, error)             { return _DataLen(rr, x...) }
func (rr *OPT) TTL(x ...dnswire.TTL) (dnswire.TTL, error)       { return _TTL(rr, x...) }
func (rr *OPT) String() string                                  { return _String(rr) }
func (rr *OPT) Len() int                                        { return _Len(rr) }
func (rr *OPT) Octets(x ...[]byte) []byte                       { return octets(rr.octets, x...) }

// format formats the args as 's1 + \t + s2 + " " + s3 + " " ...
func format(x ...string) string {
	s := strings.Builder{}
	s.WriteString(x[0])
	s.WriteByte('\t')
	for i := range len(x) - 1 {
		if i > 0 {
			s.WriteByte(' ')
		}
		s.WriteString(x[i+1])
	}
	return s.String()
}

func octets(rr []byte, x ...[]byte) []byte {
	if len(x) == 0 {
		return rr
	}
	rr = x[0]
	return nil
}
