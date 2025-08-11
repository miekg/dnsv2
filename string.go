package dns

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dnsv2/internal/ddd"
)

func sprintName(s string) string {
	var dst strings.Builder

	for i := 0; i < len(s); {
		if s[i] == '.' {
			if dst.Len() != 0 {
				dst.WriteByte('.')
			}
			i++
			continue
		}

		b, n := nextByte(s, i)
		if n == 0 {
			// Drop "dangling" incomplete escapes.
			if dst.Len() == 0 {
				return s[:i]
			}
			break
		}
		if isDomainNameLabelSpecial(b) {
			if dst.Len() == 0 {
				dst.Grow(len(s) * 2)
				dst.WriteString(s[:i])
			}
			dst.WriteByte('\\')
			dst.WriteByte(b)
		} else if b < ' ' || b > '~' { // unprintable, use \DDD
			if dst.Len() == 0 {
				dst.Grow(len(s) * 2)
				dst.WriteString(s[:i])
			}
			dst.WriteString(escapeByte(b))
		} else {
			if dst.Len() != 0 {
				dst.WriteByte(b)
			}
		}
		i += n
	}
	if dst.Len() == 0 {
		return s
	}
	return dst.String()
}

func sprintTxtOctet(s string) string {
	var dst strings.Builder
	dst.Grow(2 + len(s))
	dst.WriteByte('"')
	for i := 0; i < len(s); {
		if i+1 < len(s) && s[i] == '\\' && s[i+1] == '.' {
			dst.WriteString(s[i : i+2])
			i += 2
			continue
		}

		b, n := nextByte(s, i)
		if n == 0 {
			i++ // dangling back slash
		} else {
			writeTXTStringByte(&dst, b)
		}
		i += n
	}
	dst.WriteByte('"')
	return dst.String()
}

func sprintTxt(txt []string) string {
	var out strings.Builder
	for i, s := range txt {
		out.Grow(3 + len(s))
		if i > 0 {
			out.WriteString(` "`)
		} else {
			out.WriteByte('"')
		}
		for j := 0; j < len(s); {
			b, n := nextByte(s, j)
			if n == 0 {
				break
			}
			writeTXTStringByte(&out, b)
			j += n
		}
		out.WriteByte('"')
	}
	return out.String()
}

func writeTXTStringByte(s *strings.Builder, b byte) {
	switch {
	case b == '"' || b == '\\':
		s.WriteByte('\\')
		s.WriteByte(b)
	case b < ' ' || b > '~':
		s.WriteString(escapeByte(b))
	default:
		s.WriteByte(b)
	}
}

const (
	escapedByteSmall = "" +
		`\000\001\002\003\004\005\006\007\008\009` +
		`\010\011\012\013\014\015\016\017\018\019` +
		`\020\021\022\023\024\025\026\027\028\029` +
		`\030\031`
	escapedByteLarge = `\127\128\129` +
		`\130\131\132\133\134\135\136\137\138\139` +
		`\140\141\142\143\144\145\146\147\148\149` +
		`\150\151\152\153\154\155\156\157\158\159` +
		`\160\161\162\163\164\165\166\167\168\169` +
		`\170\171\172\173\174\175\176\177\178\179` +
		`\180\181\182\183\184\185\186\187\188\189` +
		`\190\191\192\193\194\195\196\197\198\199` +
		`\200\201\202\203\204\205\206\207\208\209` +
		`\210\211\212\213\214\215\216\217\218\219` +
		`\220\221\222\223\224\225\226\227\228\229` +
		`\230\231\232\233\234\235\236\237\238\239` +
		`\240\241\242\243\244\245\246\247\248\249` +
		`\250\251\252\253\254\255`
)

// escapeByte returns the \DDD escaping of b which must
// satisfy b < ' ' || b > '~'.
func escapeByte(b byte) string {
	if b < ' ' {
		return escapedByteSmall[b*4 : b*4+4]
	}

	b -= '~' + 1
	// The cast here is needed as b*4 may overflow byte.
	return escapedByteLarge[int(b)*4 : int(b)*4+4]
}

// isDomainNameLabelSpecial returns true if
// a domain name label byte should be prefixed
// with an escaping backslash.
func isDomainNameLabelSpecial(b byte) bool {
	switch b {
	case '.', ' ', '\'', '@', ';', '(', ')', '"', '\\':
		return true
	}
	return false
}

func nextByte(s string, offset int) (byte, int) {
	if offset >= len(s) {
		return 0, 0
	}
	if s[offset] != '\\' {
		// not an escape sequence
		return s[offset], 1
	}
	switch len(s) - offset {
	case 1: // dangling escape
		return 0, 0
	case 2, 3: // too short to be \ddd
	default: // maybe \ddd
		if ddd.Is(s[offset+1:]) {
			return ddd.ToByte(s[offset+1:]), 4
		}
	}
	// not \ddd, just an RFC 1035 "quoted" character
	return s[offset+1], 2
}

func sprintType(t uint16) string {
	if t1, ok := TypeToString[uint16(t)]; ok {
		return t1
	}
	return "TYPE" + strconv.Itoa(int(t))
}

func sprintCode(t uint16) string {
	if t1, ok := CodeToString[uint16(t)]; ok {
		return t1
	}
	return "CODE" + strconv.Itoa(int(t))
}

func sprintClass(c uint16) string {
	if s, ok := ClassToString[uint16(c)]; ok {
		// Only emit mnemonics when they are unambiguous, specially ANY is in both.
		if _, ok := StringToType[s]; !ok {
			return s
		}
	}
	return "CLASS" + strconv.Itoa(int(c))
}

// TimeToString translates the RRSIG's incep. and expir. times to the
// string representation used when printing the record.
// It takes serial arithmetic (RFC 1982) into account.
func TimeToString(t uint32) string {
	mod := (int64(t)-time.Now().Unix())/year68 - 1
	if mod < 0 {
		mod = 0
	}
	ti := time.Unix(int64(t)-mod*year68, 0).UTC()
	return ti.Format("20060102150405")
}

// StringToTime translates the RRSIG's incep. and expir. times from
// string values like "20110403154150" to an 32 bit integer.
// It takes serial arithmetic (RFC 1982) into account.
func StringToTime(s string) (uint32, error) {
	t, err := time.Parse("20060102150405", s)
	if err != nil {
		return 0, err
	}
	mod := t.Unix()/year68 - 1
	if mod < 0 {
		mod = 0
	}
	return uint32(t.Unix() - mod*year68), nil
}

// saltToString converts a NSECX salt to uppercase and returns "-" when it is empty.
func saltToString(s string) string {
	if s == "" {
		return "-"
	}
	return strings.ToUpper(s)
}

func euiToString(eui uint64, bits int) (hex string) {
	switch bits {
	case 64:
		hex = fmt.Sprintf("%16.16x", eui)
		hex = hex[0:2] + "-" + hex[2:4] + "-" + hex[4:6] + "-" + hex[6:8] +
			"-" + hex[8:10] + "-" + hex[10:12] + "-" + hex[12:14] + "-" + hex[14:16]
	case 48:
		hex = fmt.Sprintf("%12.12x", eui)
		hex = hex[0:2] + "-" + hex[2:4] + "-" + hex[4:6] + "-" + hex[6:8] +
			"-" + hex[8:10] + "-" + hex[10:12]
	}
	return
}

// sprintHeader creates a strings.Builder, write the header to it, plus an extra tab and returns the builder.
func sprintHeader(rr RR) *strings.Builder {
	sb := strings.Builder{}
	sb.WriteString(sprintName(rr.Header().Name))
	sb.WriteByte('\t')

	sb.WriteString(strconv.FormatInt(int64(rr.Header().TTL), 10))
	sb.WriteByte('\t')

	sb.WriteString(sprintClass(rr.Header().Class))
	sb.WriteByte('\t')

	rrtype := rr.Header().t
	if rrtype == 0 {
		rrtype = RRToType(rr)
	}
	sb.WriteString(sprintType(rrtype))
	sb.WriteByte('\t')
	return &sb
}

func sprintOptionHeader(rr EDNS0) *strings.Builder {
	sb := strings.Builder{}
	sb.WriteByte('.')
	sb.WriteByte('\t')

	sb.WriteByte('\t') // skip TTL

	sb.WriteString(sprintClass(rr.Header().Class))
	sb.WriteByte('\t')

	rrcode := RRToCode(rr)
	sb.WriteString(sprintCode(rrcode))
	sb.WriteByte('\t')
	return &sb
}

// sprintData write the rdata to sb with spaces between the elements
func sprintData(sb *strings.Builder, sx ...string) {
	for i, s := range sx {
		sb.WriteString(s)
		if i < len(sx)-1 {
			sb.WriteByte(' ')
		}
	}
}

func splitN(s string, n int) []string {
	if len(s) < n {
		return []string{s}
	}
	sx := []string{}
	p, i := 0, n
	for {
		if i <= len(s) {
			sx = append(sx, s[p:i])
		} else {
			sx = append(sx, s[p:])
			break

		}
		p, i = p+n, i+n
	}

	return sx
}
