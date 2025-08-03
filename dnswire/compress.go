package dnswire

import "bytes"

// compressibleType is a map of RR types that have compressible rdata.
var compressibleType = map[int]struct{}{
	15: {}, // MX
}

func decompress(octets []byte, off int, rr *bytes.Buffer) bool {
	ptr := 0
Loop:
	for {
		if off > len(octets)-1 {
			return false
		}
		c := int(octets[off])
		off++
		switch c & 0xC0 {
		case 0x00:
			if c == 0x00 { // end of the name
				rr.WriteByte(0)
				break Loop
			}
			rr.Write(octets[off-1 : off+c])
			off += c
		case 0xC0:
			if ptr++; ptr > 10 { // Every label can be a pointer, so the max is maxlabels.?
				return false
			}
			c1 := int(octets[off]) // the next octet
			off = ((c^0xC0)<<8 | c1)
		default:
			return false
		}
	}
	return true
}
