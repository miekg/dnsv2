package generate

import (
	"fmt"
	"io"
)

const overflow = `if offset+n >= len(msg) {
	return &WireError{fmt.Errorf("buffer size too small, need %d, got %d", offset+n, len(msg))}
}
`

// Uint32 writes the Go code to set an [4]byte.
func Uint32(w io.Writer, name string, last bool) {
	fmt.Fprintf(w, "%s", overflow)
	for i := 0; i < 4; i++ {
		fmt.Fprintf(w, "rr.%s[%d] = msg[offset+%d]\n", name, i, i)
	}
	offset(w, 4, last)
}

// Uint16 writes the Go code to set an [2]byte.
func Uint16(w io.Writer, name string, last bool) {
	fmt.Fprintf(w, "%s", overflow)
	for i := 0; i < 2; i++ {
		fmt.Fprintf(w, "rr.%s[%d] = msg[offset+%d]\n", name, i, i)
	}
	offset(w, 2, last)
}

// Name writes the Go code to set an Name.
func Name(w io.Writer, name string, last bool) {
	fmt.Fprintf(w, "rr.%s, offset, err = unpackName(msg, offset)\n", name)
	fmt.Fprintln(w, `if err != nil {
return err
}`)
	offset(w, 1, last)
}

// ofset writes the Go code to increase offset
func offset(w io.Writer, n int, last bool) {
	if last {
		return
	}
	if n == 1 {
		fmt.Fprintf(w, "offset++\n")
	} else {
		fmt.Fprintf(w, "offset+=%d\n", n)
	}
}
