package dns

// WireError is an error that is returned when packing or unpacking RRs fails.
type WireError struct {
	error
}

func (w *WireError) Error() string { return "dns: " + w.error.Error() }
