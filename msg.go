package dns

func (m *Msg) Octets(x ...[]byte) []byte {
	if len(x) == 0 {
		return m.octets
	}
	// TODO
	return nil
}

func (m *Msg) Question(x ...Section) Section {
	return Section{}
}
