package dns

import "encoding/binary"

// compression is used to apply compression to owner names and a few names in rdata of well known types. The returned
// uint16 is the target value for the pointer.
type compression map[string]uint16

// insert inserts name into the compression map. Name starts at offset in the message.
func (c compression) insert(n Name, offset uint16) {
	for i, stop := 0, false; !stop; i, stop = n.Next(i) {
		if len(n[i:]) == 1 {
			return
		}
		_, ok := c[string(n[i:])]
		if ok {
			continue
		}
		println("ADDING", string(n[i:]))
		c[string(n[i:])] = uint16(offset + uint16(i))
	}
}

// find finds the best compression pointer for name, the returned buffer is the truncated name buffer with compression
// pointers applied.
func (c compression) find(n Name) Name {
	pointer, ok := uint16(0), false
	for i, stop := 0, false; !stop; i, stop = n.Next(i) {
		if len(n[i:]) == 1 {
			return n
		}
		if pointer, ok = c[string(n[i:])]; ok {
			println("pointer found", pointer, string(n[i:]))
			// i and i+1 can be set to the pointer value.
			binary.BigEndian.PutUint16(n[i:], uint16(pointer^0xC000))
			println("new name", string(n[:i+2]))
			return Name(n[:i+2])
		}
	}
	// not reached
	return n
}
