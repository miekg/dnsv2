//go:build ignore

package dns

import (
	"fmt"
	"strconv"
)

func (rr *OPT) String() string {
	s := "\n;; OPT PSEUDOSECTION:\n; EDNS: version " + strconv.Itoa(int(rr.Version())) + "; "
	if rr.Do() {
		s += "flags: do; "
	} else {
		s += "flags:; "
	}
	if rr.Hdr.Ttl&0x7FFF != 0 {
		s += fmt.Sprintf("MBZ: 0x%04x, ", rr.Hdr.Ttl&0x7FFF)
	}
	s += "udp: " + strconv.Itoa(int(rr.UDPSize()))

	for _, o := range rr.Option {
		switch o.(type) {
		case *EDNS0_NSID:
			s += "\n; NSID: " + o.String()
			h, e := o.pack()
			var r string
			if e == nil {
				for _, c := range h {
					r += "(" + string(c) + ")"
				}
				s += "  " + r
			}
		case *EDNS0_SUBNET:
			s += "\n; SUBNET: " + o.String()
		case *EDNS0_COOKIE:
			s += "\n; COOKIE: " + o.String()
		case *EDNS0_EXPIRE:
			s += "\n; EXPIRE: " + o.String()
		case *EDNS0_TCP_KEEPALIVE:
			s += "\n; KEEPALIVE: " + o.String()
		case *EDNS0_UL:
			s += "\n; UPDATE LEASE: " + o.String()
		case *EDNS0_LLQ:
			s += "\n; LONG LIVED QUERIES: " + o.String()
		case *EDNS0_DAU:
			s += "\n; DNSSEC ALGORITHM UNDERSTOOD: " + o.String()
		case *EDNS0_DHU:
			s += "\n; DS HASH UNDERSTOOD: " + o.String()
		case *EDNS0_N3U:
			s += "\n; NSEC3 HASH UNDERSTOOD: " + o.String()
		case *EDNS0_LOCAL:
			s += "\n; LOCAL OPT: " + o.String()
		case *EDNS0_PADDING:
			s += "\n; PADDING: " + o.String()
		case *EDNS0_EDE:
			s += "\n; EDE: " + o.String()
		case *EDNS0_ESU:
			s += "\n; ESU: " + o.String()
		}
	}
	return s
}

func (rr *OPT) len(off int, compression map[string]struct{}) int {
	l := rr.Hdr.len(off, compression)
	for _, o := range rr.Option {
		l += 4 // Account for 2-byte option code and 2-byte option length.
		lo, _ := o.pack()
		l += len(lo)
	}
	return l
}

func (*OPT) parse(c *zlexer, origin string) *ParseError {
	return &ParseError{err: "OPT records do not have a presentation format"}
}

// Version returns the EDNS version used. Only zero is defined.
func (rr *OPT) Version() uint8 {
	return uint8(rr.Hdr.Ttl & 0x00FF0000 >> 16)
}

// SetVersion sets the version of EDNS. This is usually zero.
func (rr *OPT) SetVersion(v uint8) {
	rr.Hdr.Ttl = rr.Hdr.Ttl&0xFF00FFFF | uint32(v)<<16
}

// ExtendedRcode returns the EDNS extended RCODE field (the upper 8 bits of the TTL).
func (rr *OPT) ExtendedRcode() int {
	return int(rr.Hdr.Ttl&0xFF000000>>24) << 4
}

// SetExtendedRcode sets the EDNS extended RCODE field.
//
// If the RCODE is not an extended RCODE, will reset the extended RCODE field to 0.
func (rr *OPT) SetExtendedRcode(v uint16) {
	rr.Hdr.Ttl = rr.Hdr.Ttl&0x00FFFFFF | uint32(v>>4)<<24
}

// UDPSize returns the UDP buffer size.
func (rr *OPT) UDPSize() uint16 {
	return rr.Hdr.Class
}

// SetUDPSize sets the UDP buffer size.
func (rr *OPT) SetUDPSize(size uint16) {
	rr.Hdr.Class = size
}

// Do returns the value of the DO (DNSSEC OK) bit.
func (rr *OPT) Do() bool {
	return rr.Hdr.Ttl&_DO == _DO
}

// SetDo sets the DO (DNSSEC OK) bit.
// If we pass an argument, set the DO bit to that value.
// It is possible to pass 2 or more arguments, but they will be ignored.
func (rr *OPT) SetDo(do ...bool) {
	if len(do) == 1 {
		if do[0] {
			rr.Hdr.Ttl |= _DO
		} else {
			rr.Hdr.Ttl &^= _DO
		}
	} else {
		rr.Hdr.Ttl |= _DO
	}
}

// Z returns the Z part of the OPT RR as a uint16 with only the 15 least significant bits used.
func (rr *OPT) Z() uint16 {
	return uint16(rr.Hdr.Ttl & 0x7FFF)
}

// SetZ sets the Z part of the OPT RR, note only the 15 least significant bits of z are used.
func (rr *OPT) SetZ(z uint16) {
	rr.Hdr.Ttl = rr.Hdr.Ttl&^0x7FFF | uint32(z&0x7FFF)
}
