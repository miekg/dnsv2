package dns

import (
	"encoding/binary"

	"github.com/miekg/dnsv2/dnswire"
)

// contains rdata related function that have not yet been generated, for those see: zrdata.go

func (rr *MX) String() string { return format(_String(rr), rr.Prio().String(), rr.Mx().String()) }

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
