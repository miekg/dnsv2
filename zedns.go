// Code generated by "go run edns_generate.go"; Edits will be lost.

package dns

// OptionCode returns the option code of the Option.
func OptionCode(e Option) Code {
	switch e.(type) {
	case *COOKIE:
		return CodeCookie
	case *NSID:
		return CodeNSID
	}
	return CodeNone
}

var (
	_ Option = new(COOKIE)
	_ Option = new(NSID)
)

var codeToOption = map[Code]func() Option{
	CodeCookie: func() Option { return new(COOKIE) },
	CodeNSID:   func() Option { return new(NSID) },
}
