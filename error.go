package dns

// Error represents a DNS error.
type Error struct{ err string }

var (
	ErrBuf       error = &Error{err: "buffer size too small"} // ErrBuf indicates that the buffer used is too small for the message.
	ErrPointer   error = &Error{err: "unresolvable pointer"}  // ErrPointer indicates that we compression pointer was encountered that can not be resolved.
	ErrLabelType error = &Error{err: "bad label type"}        // ErrLabelType indicates an illegal label type was encountered.
)

func (e *Error) Error() string { return "dns: " + e.err }
