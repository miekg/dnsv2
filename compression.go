package dns

// compression is used to apply compression to owner names and a few names in rdata of well known types. The returned
// uint16 is the target value for the pointer.
type compression map[string]uint16

// insert inserts name into the compression map. Name starts at offset in the message.
func (c compression) insert(n Name, offset uint16) {
	// There is only 14 bits for compression pointer targets, so we can't use names after that as target for
	// compression pointers.
	if offset >= 2<<13 {
		return
	}
	for i, stop := 0, false; !stop; i, stop = n.Next(i) {
		if len(n[i:]) == 1 {
			return
		}

		k := string(n[i:])
		_, ok := c[k]
		if ok {
			continue
		}
		c[k] = uint16(offset + uint16(i))
	}
}

// finds finds the best (longest possible compressed name) compression pointer for n. The returned integers are the
// offset where to set the compression pointer in the name and the uint16 value of the pointer. When nothing has been
// found a 0 pointer will be returned (which is never valid in the DNS).
func (c compression) find(n Name) (offset, pointer uint16) {
	for i, stop := 0, false; !stop; i, stop = n.Next(i) {
		if len(n[i:]) == 1 {
			return 0, 0
		}
		if len(n[i:]) == 2 { // single character label, not worth compressing
			continue
		}
		if pointer, ok := c[string(n[i:])]; ok {
			return uint16(i), pointer ^ 0xC000
		}
	}
	// not reached
	return 0, 0
}
