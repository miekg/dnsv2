package dns

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"strconv"
	"strings"

	"github.com/miekg/dnsv2/dnsutil"
	"github.com/miekg/dnsv2/internal/ddd"
	"golang.org/x/crypto/cryptobyte"
)

const (
	maxCompressionOffset    = 2 << 13 // We have 14 bits for the compression pointer
	maxDomainNameWireOctets = 255     // See RFC 1035 section 2.3.4

	// This is the maximum number of compression pointers that should occur in a
	// semantically valid message. Each label in a domain name must be at least one
	// octet and is separated by a period. The root label won't be represented by a
	// compression pointer to a compression pointer, hence the -2 to exclude the
	// smallest valid root label.

	// This is the maximum length of a domain name in presentation format. The
	// maximum wire length of a domain name is 255 octets (see above), with the
	// maximum label length being 63. The wire format requires one extra byte over
	// the presentation format, reducing the number of octets by 1. Each label in
	// the name will be separated by a single period, with each octet in the label
	// expanding to at most 4 bytes (\DDD). If all other labels are of the maximum
	// length, then the final label can only be 61 octets long to not exceed the
	// maximum allowed wire length.
	maxDomainNamePresentationLength = 61*4 + 1 + 63*4 + 1 + 63*4 + 1 + 63*4 + 1
)

// ID by default returns a 16-bit random number to be used as a message id. The
// number is drawn from a cryptographically secure random number generator.
// This being a variable the function can be reassigned to a custom function.
// For instance, to make it return a static value for testing:
//
//	dns.Id = func() uint16 { return 3 }
var ID = id

// id returns a 16 bits random number to be used as a
// message id. The random provided should be good enough.
func id() uint16 {
	var output uint16
	err := binary.Read(rand.Reader, binary.BigEndian, &output)
	if err != nil {
		panic("dns: reading random id failed: " + err.Error())
	}
	return output
}

// ClassToString is a maps Classes to strings for each CLASS wire type.
var ClassToString = map[uint16]string{
	ClassINET:   "IN",
	ClassCSNET:  "CS",
	ClassCHAOS:  "CH",
	ClassHESIOD: "HS",
	ClassNONE:   "NONE",
	ClassANY:    "ANY",
}

// OpcodeToString maps Opcodes to strings.
var OpcodeToString = map[uint8]string{
	OpcodeQuery:  "QUERY",
	OpcodeIQuery: "IQUERY",
	OpcodeStatus: "STATUS",
	OpcodeNotify: "NOTIFY",
	OpcodeUpdate: "UPDATE",
}

// RcodeToString maps Rcodes to strings.
var RcodeToString = map[uint16]string{
	RcodeSuccess:        "NOERROR",
	RcodeFormatError:    "FORMERR",
	RcodeServerFailure:  "SERVFAIL",
	RcodeNameError:      "NXDOMAIN",
	RcodeNotImplemented: "NOTIMPL",
	RcodeRefused:        "REFUSED",
	RcodeYXDomain:       "YXDOMAIN", // See RFC 2136
	RcodeYXRrset:        "YXRRSET",
	RcodeNXRrset:        "NXRRSET",
	RcodeNotAuth:        "NOTAUTH",
	RcodeNotZone:        "NOTZONE",
	RcodeBadSig:         "BADSIG", // Also known as RcodeBadVers, see RFC 6891
	//	RcodeBadVers:        "BADVERS",
	RcodeBadKey:    "BADKEY",
	RcodeBadTime:   "BADTIME",
	RcodeBadMode:   "BADMODE",
	RcodeBadName:   "BADNAME",
	RcodeBadAlg:    "BADALG",
	RcodeBadTrunc:  "BADTRUNC",
	RcodeBadCookie: "BADCOOKIE",
}

// Domain names are a sequence of counted strings split at the dots. They end with a zero-length string.

func packDomainName(s string, msg []byte, off int, compression map[string]uint16, compress bool) (off1 int, err error) {
	// XXX: A logical copy of this function exists in IsDomainName and
	// should be kept in sync with this function.

	ls := len(s)
	if ls == 0 { // Ok, for instance when dealing with update RR without any rdata.
		// TODO(tmthrgd): This can produce corrupt messages and records. See
		// the comment in unpackQuestion.
		return off, nil
	}

	// If not fully qualified, error out.
	if !dnsutil.IsFqdn(s) {
		return len(msg), ErrFqdn
	}

	// Each dot ends a segment of the name.
	// We trade each dot byte for a length byte.
	// Except for escaped dots (\.), which are normal dots.
	// There is also a trailing zero.

	// Compression
	pointer := ^uint16(0)

	// Emit sequence of counted strings, chopping at dots.
	var (
		begin     int
		compBegin int
		compOff   int
		bs        []byte
		wasDot    bool
	)
loop:
	for i := 0; i < ls; i++ {
		var c byte
		if bs == nil {
			c = s[i]
		} else {
			c = bs[i]
		}

		switch c {
		case '\\':
			if off+1 > len(msg) {
				return len(msg), ErrBuf
			}

			if bs == nil {
				bs = []byte(s)
			}

			// check for \DDD
			if ddd.Is(bs[i+1:]) {
				bs[i] = ddd.ToByte(bs[i+1:])
				copy(bs[i+1:ls-3], bs[i+4:])
				ls -= 3
				compOff += 3
			} else {
				copy(bs[i:ls-1], bs[i+1:])
				ls--
				compOff++
			}

			wasDot = false
		case '.':
			if i == 0 && len(s) > 1 {
				// leading dots are not legal except for the root zone
				return len(msg), ErrName
			}

			if wasDot {
				// two dots back to back is not legal
				return len(msg), ErrName
			}
			wasDot = true

			labelLen := i - begin
			if labelLen >= 1<<6 { // top two bits of length must be clear
				return len(msg), ErrLabel
			}

			// off can already (we're in a loop) be bigger than len(msg)
			// this happens when a name isn't fully qualified
			if off+1+labelLen > len(msg) {
				return len(msg), ErrBuf
			}

			// Don't try to compress '.'
			// We should only compress when compress is true, but we should also still pick
			// up names that can be used for *future* compression(s).
			if !isRootLabel(s, bs, begin, ls) && compression != nil {
				if p, ok := compression[s[compBegin:]]; ok {
					// The first hit is the longest matching dname
					// keep the pointer offset we get back and store
					// the offset of the current name, because that's
					// where we need to insert the pointer later

					// If compress is true, we're allowed to compress this dname
					if compress {
						pointer = p // Where to point to
						break loop
					}
				} else if off < maxCompressionOffset {
					// Only offsets smaller than maxCompressionOffset can be used.
					compression[s[compBegin:]] = uint16(off)
				}
			}

			// The following is covered by the length check above.
			msg[off] = byte(labelLen)

			if bs == nil {
				copy(msg[off+1:], s[begin:i])
			} else {
				copy(msg[off+1:], bs[begin:i])
			}
			off += 1 + labelLen

			begin = i + 1
			compBegin = begin + compOff
		default:
			wasDot = false
		}
	}

	// Root label is special
	if isRootLabel(s, bs, 0, ls) {
		return off, nil
	}

	// If we did compression and we find something add the pointer here
	if pointer != ^uint16(0) {
		// We have two bytes (14 bits) to put the pointer in
		binary.BigEndian.PutUint16(msg[off:], 0xC000|pointer)
		return off + 2, nil
	}

	if off < len(msg) {
		msg[off] = 0
	}

	return off + 1, nil
}

// isRootLabel returns whether s or bs, from off to end, is the root
// label ".".
//
// If bs is nil, s will be checked, otherwise bs will be checked.
func isRootLabel(s string, bs []byte, off, end int) bool {
	if bs == nil {
		return s[off:end] == "."
	}

	return end-off == 1 && bs[off] == '.'
}

// Unpack a domain name.
// In addition to the simple sequences of counted strings above,
// domain names are allowed to refer to strings elsewhere in the
// packet, to avoid repeating common suffixes when returning
// many entries in a single domain. The pointers are marked
// by a length byte with the top two bits set. Ignoring those
// two bits, that byte and the next give a 14 bit offset from into msg
// where we should pick up the trail.
// Note that if we jump elsewhere in the packet,
// we record the last offset we read from when we found the first pointer,
// which is where the next record or record field will start.
// We enforce that pointers always point backwards into the message.

// UnpackDomainName unpacks a domain name into a string. It returns
// the name, the new offset into msg and any error that occurred.
//
// When an error is encountered, the unpacked name will be discarded
// and len(msg) will be returned as the offset.
func UnpackDomainName(msg []byte, off int) (string, int, error) {
	s := cryptobyte.String(msg[off:])
	name, err := unpackDomainName(&s, msg)
	if err != nil {
		if errors.Is(err, ErrUnpackOverflow) {
			// Keep existing behaviour of returning ErrBuf here.
			return "", len(msg), ErrBuf
		}
		// Keep documented behaviour of returning len(msg) here.
		return "", len(msg), err
	}
	return name, offset(s, msg), nil
}

func unpackDomainName(s *cryptobyte.String, msgBuf []byte) (string, error) {
	name := make([]byte, 0, maxDomainNamePresentationLength)
	budget := maxDomainNameWireOctets
	var ptrs int // number of pointers followed

	// If we never see a pointer, we need to ensure that we advance s to our final position.
	cs := *s
	defer func() {
		if ptrs == 0 {
			*s = cs
		}
	}()

	for {
		var c byte
		if !cs.ReadUint8(&c) {
			return "", ErrUnpackOverflow
		}
		switch c & 0xC0 {
		case 0x00: // literal string
			var label []byte
			if !cs.ReadBytes(&label, int(c)) {
				return "", ErrUnpackOverflow
			}
			// If we see a zero-length label (root label), this is the end of the name.
			if len(label) == 0 {
				if len(name) == 0 {
					return ".", nil
				}
				return string(name), nil
			}
			if budget -= len(label) + 1; budget <= 0 { // +1 for the label separator
				return "", ErrLongDomain
			}
			for _, b := range label {
				if isDomainNameLabelSpecial(b) {
					name = append(name, '\\', b)
				} else if b < ' ' || b > '~' {
					name = append(name, escapeByte(b)...)
				} else {
					name = append(name, b)
				}
			}
			name = append(name, '.')
		case 0xC0: // pointer
			var c1 byte
			if !cs.ReadUint8(&c1) {
				return "", ErrUnpackOverflow
			}
			// If this is the first pointer we've seen, we need to
			// advance s to our current position.
			if ptrs == 0 {
				*s = cs
			}
			// The pointer should always point backwards to an earlier
			// part of the message. Technically it could work pointing
			// forwards, but we choose not to support that as RFC1035
			// specifically refers to a "prior occurance".
			off := uint16(c&^0xC0)<<8 | uint16(c1)
			if int(off) >= offset(cs, msgBuf)-2 {
				return "", &Error{err: "pointer not to prior occurrence of name"}
			}
			// Jump to the offset in msgBuf. We carry msgBuf around with
			// us solely for this line.
			cs = msgBuf[off:]
		default: // 0x80 and 0x40 are reserved
			return "", &Error{err: "reserved domain name label type"}
		}
	}
}

// TODO(tmthrgd): Move these helper functions to msg_helpers.go.

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

// packQuestion packs an RR into a question section.
func packQuestion(rr RR, msg []byte, off int) (off1 int, err error) {
	if rr == nil {
		return len(msg), &Error{err: "nil rr"}
	}

	off, err = packDomainName(rr.Header().Name, msg, off, nil, true)
	if err != nil {
		return len(msg), err
	}
	rrtype := RRToType(rr)
	off, err = packUint16(rrtype, msg, off)
	if err != nil {
		return len(msg), err
	}

	off, err = packUint16(rr.Header().Class, msg, off)
	if err != nil {
		return len(msg), err
	}
	return off, nil
}

// PackRR packs a resource record rr into msg[off:].
// See PackDomainName for documentation about the compression.
func PackRR(rr RR, msg []byte, off int, compression map[string]uint16) (off1 int, err error) {
	_, off1, err = packRR(rr, msg, off, compression)
	return off1, err
}

func packRR(rr RR, msg []byte, off int, compression map[string]uint16) (headerEnd int, off1 int, err error) {
	if rr == nil {
		return len(msg), len(msg), &Error{err: "nil rr"}
	}

	rrtype := RRToType(rr)
	headerEnd, err = rr.Header().packHeader(msg, off, rrtype, compression)
	if err != nil {
		return headerEnd, len(msg), err
	}

	off1, err = pack(rr, msg, headerEnd, compression)
	if err != nil {
		return headerEnd, len(msg), err
	}

	rdlength := off1 - headerEnd
	if int(uint16(rdlength)) != rdlength { // overflow
		return headerEnd, len(msg), ErrLenRData
	}

	// The RDLENGTH field is the last field in the header and we set it here.
	binary.BigEndian.PutUint16(msg[headerEnd-2:], uint16(rdlength))
	return headerEnd, off1, nil
}

// UnpackRR unpacks msg[off:] into an RR.
func UnpackRR(msg []byte, off int) (rr RR, off1 int, err error) {
	if off < 0 || off > len(msg) {
		return nil, off, &Error{err: "bad offset"}
	}
	if off == len(msg) {
		// Preserve this somewhat strange existing corner case of not
		// returning an error when given nothing to unpack.
		return nil, len(msg), nil
	}

	s := cryptobyte.String(msg[off:])
	rr, err = unpackRR(&s, msg)
	return rr, offset(s, msg), err
}

func unpackRR(msg *cryptobyte.String, msgBuf []byte) (RR, error) {
	h, rdlength, err := unpackRRHeader(msg, msgBuf)
	if err != nil {
		return nil, err
	}

	return unpackRRWithHeader(h, rdlength, msg, msgBuf)
}

func unpackRRWithHeader(h Header, rdlength uint16, msg *cryptobyte.String, msgBuf []byte) (RR, error) {
	var data []byte
	if !msg.ReadBytes(&data, int(rdlength)) {
		h := h // Avoid spilling h to the heap in the happy path.
		return &h, ErrTruncatedMessage
	}

	// Restrict msgBuf to the end of the RR (the current position of msg) so
	// that we compute the correct offset in unpackDomainName.
	msgBuf = msgBuf[:offset(*msg, msgBuf)]

	var rr RR
	if newFn, ok := TypeToRR[h.t]; ok {
		rr = newFn()
		*rr.Header() = h
	} else {
		rr = &RFC3597{Hdr: h}
	}

	if len(data) == 0 {
		return rr, nil
	}

	if err := unpack(rr, data, msgBuf); err != nil {
		// TODO(tmthrgd): Do we want to return a partially filled in RR here
		// or even the RR_Header we were given like above?
		return nil, err
	}

	return rr, nil
}

// Pack packs a Msg: it is converted to to wire format.
func (m *Msg) Pack() error {
	if m.isCompressible() {
		compressions := make(map[string]uint16) // Compression pointer mappings.
		return m.pack(compressions)
	}
	return m.pack(nil)
}

func (m *Msg) pack(compression map[string]uint16) (err error) {
	if m.Rcode() < 0 || m.Rcode() > 0xFFF {
		return ErrRcode
	}

	/*
		// Set extended rcode unconditionally if we have an opt, this will allow
		// resetting the extended rcode bits if they need to.
		if opt := m.IsEdns0(); opt != nil {
			opt.SetExtendedRcode(uint16(m.Rcode()))
		} else if m.Rcode() > 0xF {
			// If Rcode is an extended one and opt is nil, error out.
			return nil, ErrExtendedRcode
		}
	*/

	// Convert convenient Msg into wire-like Header.
	var dh header
	dh.ID = m.ID
	dh.Bits = uint16(m.Opcode)<<11 | uint16(m.Rcode()&0xF)
	if m.Response {
		dh.Bits |= _QR
	}
	if m.Authoritative {
		dh.Bits |= _AA
	}
	if m.Truncated {
		dh.Bits |= _TC
	}
	if m.RecursionDesired {
		dh.Bits |= _RD
	}
	if m.RecursionAvailable {
		dh.Bits |= _RA
	}
	if m.Zero {
		dh.Bits |= _Z
	}
	if m.AuthenticatedData {
		dh.Bits |= _AD
	}
	if m.CheckingDisabled {
		dh.Bits |= _CD
	}

	dh.Qdcount = uint16(len(m.Question))
	dh.Ancount = uint16(len(m.Answer))
	dh.Nscount = uint16(len(m.Ns))
	dh.Arcount = uint16(len(m.Extra)) // pseudo !!

	// We need the uncompressed length here, because we first pack it and then compress it.
	uncompressedLen := m.Len()
	if packLen := uncompressedLen + 1; len(m.Data) < packLen {
		m.Data = make([]byte, packLen)
	}

	// Pack it in: header and then the pieces.
	off := 0
	off, err = dh.pack(m.Data, off)
	if err != nil {
		return err
	}
	for _, r := range m.Question {
		off, err = packQuestion(r, m.Data, off)
		if err != nil {
			return err
		}
		break
	}
	for _, r := range m.Answer {
		_, off, err = packRR(r, m.Data, off, compression)
		if err != nil {
			return err
		}
	}
	for _, r := range m.Ns {
		_, off, err = packRR(r, m.Data, off, compression)
		if err != nil {
			return err
		}
	}
	for _, r := range m.Extra {
		_, off, err = packRR(r, m.Data, off, compression)
		if err != nil {
			return err
		}
	}
	m.Data = m.Data[:off]
	return nil
}

// We only allow a single question in the question section.
func unpackQuestion(msg *cryptobyte.String, msgBuf []byte) (RR, error) {
	// TODO(tmthrgd): Stop accepting partial questions. These are here
	// ostensibly for dynamic updates (see RFC 2136), but that standard doesn't
	// actually permit partial question records and this seems to be a hold over
	// of earlier unpacking code that was more generic. Instead we should
	// enforce that we've properly received an entire question by removing the
	// msg.Empty() checks.

	name, err := unpackDomainName(msg, msgBuf)
	if err != nil {
		if errors.Is(err, ErrUnpackOverflow) {
			return nil, ErrTruncatedMessage
		}
		return nil, err
	}
	var qtype uint16
	if !msg.Empty() && !msg.ReadUint16(&qtype) {
		return nil, ErrTruncatedMessage
	}

	// There was a bug in the previous unpacking code that meant the effective
	// behaviour when exactly one byte remained here instead of two or more
	// required for the class was to skip over it rather than return an error as
	// expected. While that may seem unremarkable on its own, there is a bug, or
	// perhaps an interesting design choice, in packDomainName means that we can
	// accidentally generate corrupt messages that would trip this very check.
	// This can happen when packing a message that contains exactly one question
	// with an empty domain name. For messages that contain either multiple
	// questions or also contain records, this is likely to lead to corrupt
	// messages that wouldn't trip this check.
	//
	// if len(*msg) == 1 {
	//      msg.Skip(1)
	//      return q, nil
	// }

	var qclass uint16
	if !msg.Empty() && !msg.ReadUint16(&qclass) {
		return nil, ErrTruncatedMessage
	}

	var rr RR
	if newFn, ok := TypeToRR[qtype]; ok {
		rr = newFn()
		*rr.Header() = Header{Name: name, t: qtype, Class: qclass}
	} else {
		rr = &RFC3597{Hdr: Header{Name: name, t: qtype, Class: qclass}}
	}

	return rr, nil
}

func unpackQuestions(cnt uint16, msg *cryptobyte.String, msgBuf []byte) ([]RR, error) {
	// We don't preallocate dst according to cnt as that value may be attacker
	// controlled. A malicious adversary could send us as 12-byte packet
	// containing only the header that claims to contain 65535 questions. As
	// Question takes 24-bytes, we'd end up allocating more than 1.5MiB from a
	// mere 12-byte packet.
	var dst []RR
	for i := 0; i < int(cnt); i++ {
		// msg is already empty, cnt is a lie.
		//
		// TODO(tmthrgd): Remove this to fix #1492.
		if msg.Empty() {
			return dst, nil
		}

		r, err := unpackQuestion(msg, msgBuf)
		if err != nil {
			return dst, err
		}
		dst = append(dst, r)
	}
	return dst, nil
}

func unpackRRs(cnt uint16, msg *cryptobyte.String, msgBuf []byte) ([]RR, error) {
	// See unpackQuestions for why we don't pre-allocate here.
	var dst []RR
	for i := 0; i < int(cnt); i++ {
		// msg is already empty, cnt is a lie.
		//
		// TODO(tmthrgd): Remove this to fix #1492.
		if msg.Empty() {
			return dst, nil
		}

		r, err := unpackRR(msg, msgBuf)
		if err != nil {
			return dst, err
		}
		dst = append(dst, r)
	}
	return dst, nil
}

func (m *Msg) unpack(dh header, msg, msgBuf []byte) error {
	s := cryptobyte.String(msg)
	// If we are at the end of the message we should return *just* the
	// header. This can still be useful to the caller. 9.9.9.9 sends these
	// when responding with REFUSED for instance.
	//
	// TODO(tmthrgd): Remove this. If it's only sending the header, the header
	// should be specifying that it contains no records.
	if s.Empty() {
		// reset sections before returning
		m.Question, m.Answer, m.Ns, m.Extra, m.Pseudo = nil, nil, nil, nil, nil
		return nil
	}

	var err error
	m.Question, err = unpackQuestions(dh.Qdcount, &s, msgBuf)
	if err != nil {
		return err
	}

	m.Answer, err = unpackRRs(dh.Ancount, &s, msgBuf)
	if err != nil {
		return err
	}

	m.Ns, err = unpackRRs(dh.Nscount, &s, msgBuf)
	if err != nil {
		return err
	}

	m.Extra, err = unpackRRs(dh.Arcount, &s, msgBuf)
	if err != nil {
		return err
	}

	if !s.Empty() {
		return &Error{err: "trailing message data"}
	}

	return nil
}

// Unpack unpacks a binary message to a Msg structure.
func (m *Msg) Unpack(msg []byte) error {
	s := cryptobyte.String(msg)
	var dh header
	if !dh.unpack(&s) {
		return ErrTruncatedMessage
	}
	m.setMsgHeader(dh)
	return m.unpack(dh, s, msg)
}

// Convert a complete message to a string with dig-like output.
func (m *Msg) String() string {
	if m == nil {
		return "<nil> MsgHdr"
	}
	sb := strings.Builder{}

	sb.WriteString(m.MsgHeader.String())
	sb.WriteByte(' ')
	sections := [4]string{"QUERY", "ANSWER", "AUTHORITY", "ADDITIONAL"}
	if m.MsgHeader.Opcode == OpcodeUpdate {
		sections = [4]string{"ZONE", "PREREQ", "UPDATE", "ADDITIONAL"}
	}
	sb.WriteString(sections[0])
	sb.WriteString(": ")
	sb.WriteString(strconv.Itoa(len(m.Question)))
	sb.WriteString(", ")

	sb.WriteString(sections[1])
	sb.WriteString(": ")
	sb.WriteString(strconv.Itoa(len(m.Answer)))
	sb.WriteString(", ")

	sb.WriteString(sections[2])
	sb.WriteString(": ")
	sb.WriteString(strconv.Itoa(len(m.Ns)))
	sb.WriteString(", ")

	sb.WriteString(sections[3])
	sb.WriteString(": ")
	sb.WriteString(strconv.Itoa(len(m.Extra)))
	sb.WriteByte('\n')

	if len(m.Question) > 0 {
		sb.WriteString(";; ")
		sb.WriteString(sections[0])
		sb.WriteString(" SECTION:\n")
		for _, r := range m.Question {
			sb.WriteString(r.String())
			sb.WriteByte('\n')
		}
	}
	if len(m.Answer) > 0 {
		sb.WriteString(";; ")
		sb.WriteString(sections[1])
		sb.WriteString(" SECTION:\n")
		for _, r := range m.Answer {
			sb.WriteString(r.String())
			sb.WriteByte('\n')
		}
	}
	if len(m.Ns) > 0 {
		sb.WriteString(";; ")
		sb.WriteString(sections[2])
		sb.WriteString(" SECTION:\n")
		for _, r := range m.Ns {
			sb.WriteString(r.String())
			sb.WriteByte('\n')
		}
	}
	if len(m.Extra) > 0 {
		sb.WriteString(";; ")
		sb.WriteString(sections[3])
		sb.WriteString(" SECTION:\n")
		for _, r := range m.Extra {
			sb.WriteString(r.String())
			sb.WriteByte('\n')
		}
	}
	return sb.String()
}

// isCompressible returns whether the msg may be compressible.
func (m *Msg) isCompressible() bool {
	// If we only have one question, there is nothing we can ever compress.
	return len(m.Question) > 1 || len(m.Answer) > 0 ||
		len(m.Ns) > 0 || len(m.Extra) > 0
}

// Len returns the message length when in uncompressed wire format.
func (m *Msg) Len() int {
	l := MsgHeaderSize

	for _, r := range m.Question {
		l += r.Len()
	}
	for _, r := range m.Answer {
		if r != nil {
			l += r.Len()
		}
	}
	for _, r := range m.Ns {
		if r != nil {
			l += r.Len()
		}
	}
	for _, r := range m.Extra {
		if r != nil {
			l += r.Len()
		}
	}

	return l
}

func (dh *header) pack(msg []byte, off int) (int, error) {
	off, err := packUint16(dh.ID, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint16(dh.Bits, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint16(dh.Qdcount, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint16(dh.Ancount, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint16(dh.Nscount, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint16(dh.Arcount, msg, off)
	if err != nil {
		return off, err
	}
	return off, nil
}

func (dh *header) unpack(msg *cryptobyte.String) bool {
	return msg.ReadUint16(&dh.ID) &&
		msg.ReadUint16(&dh.Bits) &&
		msg.ReadUint16(&dh.Qdcount) &&
		msg.ReadUint16(&dh.Ancount) &&
		msg.ReadUint16(&dh.Nscount) &&
		msg.ReadUint16(&dh.Arcount)
}

// setHdr set the header in the dns using the binary data in dh.
func (m *Msg) setMsgHeader(dh header) {
	m.ID = dh.ID
	m.Response = dh.Bits&_QR != 0
	m.Opcode = uint8(dh.Bits>>11) & 0xF
	m.Authoritative = dh.Bits&_AA != 0
	m.Truncated = dh.Bits&_TC != 0
	m.RecursionDesired = dh.Bits&_RD != 0
	m.RecursionAvailable = dh.Bits&_RA != 0
	m.Zero = dh.Bits&_Z != 0 // _Z covers the zero bit, which should be zero; not sure why we set it to the opposite.
	m.AuthenticatedData = dh.Bits&_AD != 0
	m.CheckingDisabled = dh.Bits&_CD != 0
	m.SetRcode(dh.Bits & 0xF)
}
