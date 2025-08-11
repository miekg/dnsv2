package dns

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"sort"
	"strings"

	"github.com/miekg/dnsv2/internal/ddd"
	"golang.org/x/crypto/cryptobyte"
)

// offset reports the offset of data into buf, that is reports off such that
// &data[0] == &buf[off]. It panics if data is not buf[off:].
func offset(data, buf []byte) int {
	if len(data) > 0 && len(buf) > 0 && &data[len(data)-1] != &buf[len(buf)-1] {
		panic("dns: internal error: cannot compute offset")
	}
	return len(buf) - len(data)
}

// helper functions called from the generated zmsg.go - among others

func unpackA(s *cryptobyte.String) (net.IP, error) {
	ip := make(net.IP, net.IPv4len)
	if !s.CopyBytes(ip) {
		return nil, ErrUnpackOverflow
	}
	return ip, nil
}

func packA(a net.IP, msg []byte, off int) (int, error) {
	switch len(a) {
	case net.IPv4len, net.IPv6len:
		// It must be a slice of 4, even if it is 16, we encode only the first 4
		if off+net.IPv4len > len(msg) {
			return len(msg), &Error{err: "overflow packing a"}
		}

		copy(msg[off:], a.To4())
		off += net.IPv4len
	default:
		return len(msg), &Error{err: "overflow packing a"}
	}
	return off, nil
}

func unpackAAAA(s *cryptobyte.String) (net.IP, error) {
	ip := make(net.IP, net.IPv6len)
	if !s.CopyBytes(ip) {
		return nil, ErrUnpackOverflow
	}
	return ip, nil
}

func packAAAA(aaaa net.IP, msg []byte, off int) (int, error) {
	switch len(aaaa) {
	case net.IPv6len:
		if off+net.IPv6len > len(msg) {
			return len(msg), &Error{err: "overflow packing aaaa"}
		}

		copy(msg[off:], aaaa)
		off += net.IPv6len
	default:
		return len(msg), &Error{err: "overflow packing aaaa"}
	}
	return off, nil
}

// unpackRRHeader unpacks an RR header advancing msg.
func unpackRRHeader(msg *cryptobyte.String, msgBuf []byte) (h Header, rdlength uint16, err error) {
	h.Name, err = unpackName(msg, msgBuf)
	if err != nil {
		if errors.Is(err, ErrUnpackOverflow) {
			return h, 0, ErrTruncatedMessage
		}
		return h, 0, err
	}
	if !msg.ReadUint16(&h.t) ||
		!msg.ReadUint16(&h.Class) ||
		!msg.ReadUint32(&h.TTL) ||
		!msg.ReadUint16(&rdlength) {
		return h, rdlength, ErrTruncatedMessage
	}
	return h, rdlength, nil
}

// packHeader packs an RR header, returning the offset to the end of the header.
// See PackDomainName for documentation about the compression.
func (h Header) packHeader(msg []byte, off int, rrtype uint16, compress map[string]uint16) (int, error) {
	if off == len(msg) {
		return off, nil
	}

	off, err := packDomainName(h.Name, msg, off, compress, true)
	if err != nil {
		return len(msg), err
	}
	off, err = packUint16(rrtype, msg, off)
	if err != nil {
		return len(msg), err
	}

	class := uint16(0)
	if h.Class == 0 {
		class = ClassINET
	}
	off, err = packUint16(class, msg, off)
	if err != nil {
		return len(msg), err
	}
	off, err = packUint32(h.TTL, msg, off)
	if err != nil {
		return len(msg), err
	}
	off, err = packUint16(0, msg, off) // The RDLENGTH field will be set later in packRR.
	if err != nil {
		return len(msg), err
	}
	return off, nil
}

// helper helper functions.

var base32HexNoPadEncoding = base32.HexEncoding.WithPadding(base32.NoPadding)

func fromBase32(s []byte) (buf []byte, err error) {
	for i, b := range s {
		if b >= 'a' && b <= 'z' {
			s[i] = b - 32
		}
	}
	buflen := base32HexNoPadEncoding.DecodedLen(len(s))
	buf = make([]byte, buflen)
	n, err := base32HexNoPadEncoding.Decode(buf, s)
	buf = buf[:n]
	return
}

func toBase32(b []byte) string {
	return base32HexNoPadEncoding.EncodeToString(b)
}

func fromBase64(s []byte) (buf []byte, err error) {
	buflen := base64.StdEncoding.DecodedLen(len(s))
	buf = make([]byte, buflen)
	n, err := base64.StdEncoding.Decode(buf, s)
	buf = buf[:n]
	return
}

func toBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func packUint8(i uint8, msg []byte, off int) (off1 int, err error) {
	if off+1 > len(msg) {
		return len(msg), &Error{err: "overflow packing uint8"}
	}
	msg[off] = i
	return off + 1, nil
}

func packUint16(i uint16, msg []byte, off int) (off1 int, err error) {
	if off+2 > len(msg) {
		return len(msg), &Error{err: "overflow packing uint16"}
	}
	binary.BigEndian.PutUint16(msg[off:], i)
	return off + 2, nil
}

func packUint32(i uint32, msg []byte, off int) (off1 int, err error) {
	if off+4 > len(msg) {
		return len(msg), &Error{err: "overflow packing uint32"}
	}
	binary.BigEndian.PutUint32(msg[off:], i)
	return off + 4, nil
}

func packUint48(i uint64, msg []byte, off int) (off1 int, err error) {
	if off+6 > len(msg) {
		return len(msg), &Error{err: "overflow packing uint64 as uint48"}
	}
	msg[off] = byte(i >> 40)
	msg[off+1] = byte(i >> 32)
	msg[off+2] = byte(i >> 24)
	msg[off+3] = byte(i >> 16)
	msg[off+4] = byte(i >> 8)
	msg[off+5] = byte(i)
	off += 6
	return off, nil
}

func packUint64(i uint64, msg []byte, off int) (off1 int, err error) {
	if off+8 > len(msg) {
		return len(msg), &Error{err: "overflow packing uint64"}
	}
	binary.BigEndian.PutUint64(msg[off:], i)
	off += 8
	return off, nil
}

func unpackString(s *cryptobyte.String) (string, error) {
	var txt cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&txt) {
		return "", ErrUnpackOverflow
	}
	var sb strings.Builder
	consumed := 0
	for i, b := range txt {
		switch {
		case b == '"' || b == '\\':
			if consumed == 0 {
				sb.Grow(len(txt) * 2)
			}
			sb.Write(txt[consumed:i])
			sb.WriteByte('\\')
			sb.WriteByte(b)
			consumed = i + 1
		case b < ' ' || b > '~': // unprintable
			if consumed == 0 {
				sb.Grow(len(txt) * 2)
			}
			sb.Write(txt[consumed:i])
			sb.WriteString(escapeByte(b))
			consumed = i + 1
		}
	}
	if consumed == 0 { // no escaping needed
		return string(txt), nil
	}
	sb.Write(txt[consumed:])
	return sb.String(), nil
}

func packString(s string, msg []byte, off int) (int, error) {
	off, err := packTxtString(s, msg, off)
	if err != nil {
		return len(msg), err
	}
	return off, nil
}

func unpackStringBase32(s *cryptobyte.String, len int) (string, error) {
	var b []byte
	if !s.ReadBytes(&b, len) {
		return "", ErrUnpackOverflow
	}
	return toBase32(b), nil
}

func packStringBase32(s string, msg []byte, off int) (int, error) {
	b32, err := fromBase32([]byte(s))
	if err != nil {
		return len(msg), err
	}
	if off+len(b32) > len(msg) {
		return len(msg), &Error{err: "overflow packing base32"}
	}
	copy(msg[off:off+len(b32)], b32)
	off += len(b32)
	return off, nil
}

func unpackStringBase64(s *cryptobyte.String, len int) (string, error) {
	var b []byte
	if !s.ReadBytes(&b, len) {
		return "", ErrUnpackOverflow
	}
	return toBase64(b), nil
}

func packStringBase64(s string, msg []byte, off int) (int, error) {
	b64, err := fromBase64([]byte(s))
	if err != nil {
		return len(msg), err
	}
	if off+len(b64) > len(msg) {
		return len(msg), &Error{err: "overflow packing base64"}
	}
	copy(msg[off:off+len(b64)], b64)
	off += len(b64)
	return off, nil
}

func unpackStringHex(s *cryptobyte.String, len int) (string, error) {
	var b []byte
	if !s.ReadBytes(&b, len) {
		return "", ErrUnpackOverflow
	}
	return hex.EncodeToString(b), nil
}

func packStringHex(s string, msg []byte, off int) (int, error) {
	h, err := hex.DecodeString(s)
	if err != nil {
		return len(msg), err
	}
	if off+len(h) > len(msg) {
		return len(msg), &Error{err: "overflow packing hex"}
	}
	copy(msg[off:off+len(h)], h)
	off += len(h)
	return off, nil
}

func unpackStringAny(s *cryptobyte.String, len int) (string, error) {
	var b []byte
	if !s.ReadBytes(&b, len) {
		return "", ErrUnpackOverflow
	}
	return string(b), nil
}

func packStringAny(s string, msg []byte, off int) (int, error) {
	if off+len(s) > len(msg) {
		return len(msg), &Error{err: "overflow packing anything"}
	}
	copy(msg[off:off+len(s)], s)
	off += len(s)
	return off, nil
}

func unpackStringTxt(s *cryptobyte.String) ([]string, error) {
	return unpackTxt(s)
}

func packStringTxt(s []string, msg []byte, off int) (int, error) {
	off, err := packTxt(s, msg, off)
	if err != nil {
		return len(msg), err
	}
	return off, nil
}

func unpackOpt(s *cryptobyte.String) ([]EDNS0, error) {
	edns0 := []EDNS0{}
	for !s.Empty() {
		var (
			code uint16
			data cryptobyte.String
		)
		if !s.ReadUint16(&code) || !s.ReadUint16LengthPrefixed(&data) {
			return nil, ErrUnpackOverflow
		}
		var option EDNS0
		if newFn, ok := CodeToRR[code]; ok {
			option = newFn()
		} else {
			return nil, ErrOpt
		}
		if err := unpackOptionCode(option, &data); err != nil {
			return nil, err
		}
		edns0 = append(edns0, option)
	}
	return edns0, nil
}

func packOpt(options []EDNS0, msg []byte, off int) (int, error) {
	return 0, nil
}

func unpackStringOctet(s *cryptobyte.String) (string, error) {
	return unpackStringAny(s, len(*s))
}

func packStringOctet(s string, msg []byte, off int) (int, error) {
	off, err := packOctetString(s, msg, off)
	if err != nil {
		return len(msg), err
	}
	return off, nil
}

func unpackNsec(s *cryptobyte.String) ([]uint16, error) {
	var nsec []uint16
	lastwindow := -1
	for !s.Empty() {
		var (
			window byte
			bits   cryptobyte.String
		)
		if !s.ReadUint8(&window) ||
			!s.ReadUint8LengthPrefixed(&bits) {
			return nsec, ErrUnpackOverflow
		}
		if int(window) <= lastwindow {
			// RFC 4034: Blocks are present in the NSEC RR RDATA in
			// increasing numerical order.
			return nsec, &Error{err: "out of order NSEC(3) block in type bitmap"}
		}
		if len(bits) == 0 {
			// RFC 4034: Blocks with no types present MUST NOT be included.
			return nsec, &Error{err: "empty NSEC(3) block in type bitmap"}
		}
		if len(bits) > 32 {
			return nsec, &Error{err: "NSEC(3) block too long in type bitmap"}
		}

		// Walk the bytes in the window and extract the type bits
		for i, b := range bits {
			for n := uint(0); n < 8; n++ {
				if b&(1<<(7-n)) != 0 {
					nsec = append(nsec, uint16(int(window)*256+i*8+int(n)))
				}
			}
		}

		lastwindow = int(window)
	}
	return nsec, nil
}

// typeBitMapLen is a helper function which computes the "maximum" length of
// a the NSEC Type BitMap field.
func typeBitMapLen(bitmap []uint16) int {
	var l int
	var lastwindow, lastlength uint16
	for _, t := range bitmap {
		window := t / 256
		length := (t-window*256)/8 + 1
		if window > lastwindow && lastlength != 0 { // New window, jump to the new offset
			l += int(lastlength) + 2
			lastlength = 0
		}
		if window < lastwindow || length < lastlength {
			// packNsec would return Error{err: "nsec bits out of order"} here, but
			// when computing the length, we want do be liberal.
			continue
		}
		lastwindow, lastlength = window, length
	}
	l += int(lastlength) + 2
	return l
}

func packNsec(bitmap []uint16, msg []byte, off int) (int, error) {
	if len(bitmap) == 0 {
		return off, nil
	}
	if off > len(msg) {
		return off, &Error{err: "overflow packing nsec"}
	}
	toZero := msg[off:]
	if maxLen := typeBitMapLen(bitmap); maxLen < len(toZero) {
		toZero = toZero[:maxLen]
	}
	for i := range toZero {
		toZero[i] = 0
	}
	var lastwindow, lastlength uint16
	for _, t := range bitmap {
		window := t / 256
		length := (t-window*256)/8 + 1
		if window > lastwindow && lastlength != 0 { // New window, jump to the new offset
			off += int(lastlength) + 2
			lastlength = 0
		}
		if window < lastwindow || length < lastlength {
			return len(msg), &Error{err: "nsec bits out of order"}
		}
		if off+2+int(length) > len(msg) {
			return len(msg), &Error{err: "overflow packing nsec"}
		}
		// Setting the window #
		msg[off] = byte(window)
		// Setting the octets length
		msg[off+1] = byte(length)
		// Setting the bit value for the type in the right octet
		msg[off+1+int(length)] |= byte(1 << (7 - t%8))
		lastwindow, lastlength = window, length
	}
	off += int(lastlength) + 2
	return off, nil
}

func unpackSVCB(s *cryptobyte.String) ([]SVCBKeyValue, error) {
	var kvs []SVCBKeyValue
	for !s.Empty() {
		var (
			code uint16
			data cryptobyte.String
		)
		if !s.ReadUint16(&code) ||
			!s.ReadUint16LengthPrefixed(&data) {
			return nil, ErrUnpackOverflow
		}
		kv := makeSVCBKeyValue(SVCBKey(code))
		if kv == nil {
			return nil, &Error{err: "bad SVCB key"}
		}
		if err := kv.unpack(data); err != nil {
			return nil, err
		}
		if len(kvs) > 0 && kv.Key() <= kvs[len(kvs)-1].Key() {
			return nil, &Error{err: "SVCB keys not in strictly increasing order"}
		}
		kvs = append(kvs, kv)
	}
	return kvs, nil
}

func packSVCB(pairs []SVCBKeyValue, msg []byte, off int) (int, error) {
	pairs = cloneSlice(pairs)
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].Key() < pairs[j].Key()
	})
	prev := svcb_RESERVED
	for _, el := range pairs {
		if el.Key() == prev {
			return len(msg), &Error{err: "repeated SVCB keys are not allowed"}
		}
		prev = el.Key()
		packed, err := el.pack()
		if err != nil {
			return len(msg), err
		}
		off, err = packUint16(uint16(el.Key()), msg, off)
		if err != nil {
			return len(msg), &Error{err: "overflow packing SVCB"}
		}
		off, err = packUint16(uint16(len(packed)), msg, off)
		if err != nil || off+len(packed) > len(msg) {
			return len(msg), &Error{err: "overflow packing SVCB"}
		}
		copy(msg[off:off+len(packed)], packed)
		off += len(packed)
	}
	return off, nil
}

func unpackNames(s *cryptobyte.String, msgBuf []byte) ([]string, error) {
	var names []string
	for !s.Empty() {
		name, err := unpackName(s, msgBuf)
		if err != nil {
			return names, err
		}
		names = append(names, name)
	}
	return names, nil
}

func packDomainNames(names []string, msg []byte, off int, compress map[string]uint16) (int, error) {
	var err error
	for _, name := range names {
		off, err = packDomainName(name, msg, off, compress, false)
		if err != nil {
			return len(msg), err
		}
	}
	return off, nil
}

func packApl(data []APLPrefix, msg []byte, off int) (int, error) {
	var err error
	for i := range data {
		off, err = packAplPrefix(&data[i], msg, off)
		if err != nil {
			return len(msg), err
		}
	}
	return off, nil
}

func packAplPrefix(p *APLPrefix, msg []byte, off int) (int, error) {
	if len(p.Network.IP) != len(p.Network.Mask) {
		return len(msg), &Error{err: "address and mask lengths don't match"}
	}

	var err error
	prefix, _ := p.Network.Mask.Size()
	addr := p.Network.IP.Mask(p.Network.Mask)[:(prefix+7)/8]

	switch len(p.Network.IP) {
	case net.IPv4len:
		off, err = packUint16(1, msg, off)
	case net.IPv6len:
		off, err = packUint16(2, msg, off)
	default:
		err = &Error{err: "unrecognized address family"}
	}
	if err != nil {
		return len(msg), err
	}

	off, err = packUint8(uint8(prefix), msg, off)
	if err != nil {
		return len(msg), err
	}

	var n uint8
	if p.Negation {
		n = 0x80
	}

	// trim trailing zero bytes as specified in RFC3123 Sections 4.1 and 4.2.
	i := len(addr) - 1
	for ; i >= 0 && addr[i] == 0; i-- {
	}
	addr = addr[:i+1]

	adflen := uint8(len(addr)) & 0x7f
	off, err = packUint8(n|adflen, msg, off)
	if err != nil {
		return len(msg), err
	}

	if off+len(addr) > len(msg) {
		return len(msg), &Error{err: "overflow packing APL prefix"}
	}
	off += copy(msg[off:], addr)

	return off, nil
}

func unpackApl(s *cryptobyte.String) ([]APLPrefix, error) {
	var prefixes []APLPrefix
	for !s.Empty() {
		prefix, err := unpackAplPrefix(s)
		if err != nil {
			return nil, err
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func unpackAplPrefix(s *cryptobyte.String) (APLPrefix, error) {
	var (
		family       uint16
		prefix, nlen byte
	)
	if !s.ReadUint16(&family) ||
		!s.ReadUint8(&prefix) ||
		!s.ReadUint8(&nlen) {
		return APLPrefix{}, ErrUnpackOverflow
	}

	var ip net.IP
	switch family {
	case 1:
		ip = make(net.IP, net.IPv4len)
	case 2:
		ip = make(net.IP, net.IPv6len)
	default:
		return APLPrefix{}, &Error{err: "unrecognized APL address family"}
	}
	if int(prefix) > 8*len(ip) {
		return APLPrefix{}, &Error{err: "APL prefix too long"}
	}
	afdlen := int(nlen & 0x7f)
	if afdlen > len(ip) {
		return APLPrefix{}, &Error{err: "APL length too long"}
	}
	if !s.CopyBytes(ip[:afdlen]) {
		return APLPrefix{}, ErrUnpackOverflow
	}

	// Address MUST NOT contain trailing zero bytes per RFC3123 Sections 4.1 and 4.2.
	if afdlen > 0 && ip[afdlen-1] == 0 {
		return APLPrefix{}, &Error{err: "extra APL address bits"}
	}

	return APLPrefix{
		Negation: nlen&0x80 != 0,
		Network: net.IPNet{
			IP:   ip,
			Mask: net.CIDRMask(int(prefix), 8*len(ip)),
		},
	}, nil
}

func unpackIPSECGateway(s *cryptobyte.String, msgBuf []byte, gatewayType uint8) (net.IP, string, error) {
	var (
		addr net.IP
		name string
		err  error
	)
	switch gatewayType {
	case IPSECGatewayNone: // do nothing
	case IPSECGatewayIPv4:
		addr, err = unpackA(s)
	case IPSECGatewayIPv6:
		addr, err = unpackAAAA(s)
	case IPSECGatewayHost:
		name, err = unpackName(s, msgBuf)
	}
	return addr, name, err
}

func packIPSECGateway(gatewayAddr net.IP, gatewayString string, msg []byte, off int, gatewayType uint8, compression map[string]uint16, compress bool) (int, error) {
	var err error

	switch gatewayType {
	case IPSECGatewayNone: // do nothing
	case IPSECGatewayIPv4:
		off, err = packA(gatewayAddr, msg, off)
	case IPSECGatewayIPv6:
		off, err = packAAAA(gatewayAddr, msg, off)
	case IPSECGatewayHost:
		off, err = packDomainName(gatewayString, msg, off, compression, compress)
	}

	return off, err
}

func packTxt(txt []string, msg []byte, offset int) (int, error) {
	if len(txt) == 0 {
		if offset >= len(msg) {
			return offset, ErrBuf
		}
		msg[offset] = 0
		return offset, nil
	}
	var err error
	for _, s := range txt {
		offset, err = packTxtString(s, msg, offset)
		if err != nil {
			return offset, err
		}
	}
	return offset, nil
}

func packTxtString(s string, msg []byte, offset int) (int, error) {
	lenByteOffset := offset
	if offset >= len(msg) || len(s) > 256*4+1 /* If all \DDD */ {
		return offset, ErrBuf
	}
	offset++
	for i := 0; i < len(s); i++ {
		if len(msg) <= offset {
			return offset, ErrBuf
		}
		if s[i] == '\\' {
			i++
			if i == len(s) {
				break
			}
			// check for \DDD
			if ddd.Is(s[i:]) {
				msg[offset] = ddd.ToByte(s[i:])
				i += 2
			} else {
				msg[offset] = s[i]
			}
		} else {
			msg[offset] = s[i]
		}
		offset++
	}
	l := offset - lenByteOffset - 1
	if l > 255 {
		return offset, &Error{err: "string exceeded 255 bytes in txt"}
	}
	msg[lenByteOffset] = byte(l)
	return offset, nil
}

func packOctetString(s string, msg []byte, offset int) (int, error) {
	if offset >= len(msg) || len(s) > 256*4+1 {
		return offset, ErrBuf
	}
	for i := 0; i < len(s); i++ {
		if len(msg) <= offset {
			return offset, ErrBuf
		}
		if s[i] == '\\' {
			i++
			if i == len(s) {
				break
			}
			// check for \DDD
			if ddd.Is(s[i:]) {
				msg[offset] = ddd.ToByte(s[i:])
				i += 2
			} else {
				msg[offset] = s[i]
			}
		} else {
			msg[offset] = s[i]
		}
		offset++
	}
	return offset, nil
}

func unpackTxt(s *cryptobyte.String) ([]string, error) {
	var strs []string
	for !s.Empty() {
		str, err := unpackString(s)
		if err != nil {
			return strs, err
		}
		strs = append(strs, str)
	}
	return strs, nil
}
