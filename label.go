package dns

// Next returns the index of the next label of n. The returned bool indicates the end as been reached.
// The last index returned is the positon of the root "label".
func (n Name) Next(i int) (int, bool) {
	if i >= len(n) {
		return i, true
	}
	// See SkipName as they look too similar.
	j := n[i]
	switch {
	case j == 0:
		return i, true
	case j&0xC0 == 0xC0:
		// this should not happen here, with a parsed Name... next octet contains (rest of) the pointer value.
		return i + 1, true
	}
	return i + int(j) + 1, false
}
