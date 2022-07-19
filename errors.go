package dns

// DataError is returned when SetData returns an error.
type DataError string

func (d DataError) Error() string {
	return "dns: " + string(d)
}

// ParseError is returned when any (text) parsing fails.
type ParseError string

func (p ParseError) Error() string {
	return "dns: " + string(p)
}
