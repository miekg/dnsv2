package dns

// Msg contains the layout of a DNS message.
type Msg struct {
	octets []byte
}

func (m *Msg) Octets(x ...[]byte) []byte {
	if len(x) == 0 {
		return m.octets
	}
	// TODO
	return nil
}
