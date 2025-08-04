package dns

// Compress performs DNS name compression on the entire message. After this you should not add more RRs to
// the message because this messes up the compression pointers (unless you add at the end, either the
// Additional or Pseudo section).
func (m *Msg) Compress() {
	// todo
}

// Uncompress resolves all compression pointers in the message.
func (m *Msg) Uncompress() {
}
