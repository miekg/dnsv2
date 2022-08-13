//go:build ignore

// See types_generate.go. This generator generates the Write() methods the RRs.

package main

import (
	"bytes"
	"fmt"
	"go/types"
	"log"
	"strings"

	"github.com/miekg/dnsv2/internal/generate"
)

const overflow = `if offset+n > len(msg) {
	return &WireError{fmt.Errorf("buffer size too small, need %d, got %d", offset+n, len(msg))}
}
`

func main() {
	pkg, err := generate.Load()
	if err != nil {
		log.Fatal(err)
	}

	b := &bytes.Buffer{}
	generate.Hdr(b, "writes", []string{"fmt"})
	Write(b, pkg)

	if err := generate.SaveSource(b.Bytes(), "zwrite.go"); err != nil {
		log.Printf("%s\n", b)
		log.Fatal("failed to save source: %s", err)
	}
}

// Generate the Write() methods.
func Write(b *bytes.Buffer, pkg *types.Package) {
	typex := generate.Types(pkg, "Type")
	scope := pkg.Scope()

Types:
	for _, name := range typex {
		o := scope.Lookup(name)
		rr := generate.RR(o.Type(), scope)
		if rr == nil {
			continue
		}

		// check if this type doesn't need a Write() method to be generated.
		for i := 1; i < rr.NumFields(); i++ {
			if strings.Contains(rr.Tag(i), "-write") {
				continue Types
			}
		}

		fmt.Fprintf(b, "func (rr *%s) Write(msg []byte, offset, n int) (err error) {\n", name)
		fmt.Fprintln(b, overflow)

		for i := 1; i < rr.NumFields(); i++ {
			switch {
			// case strings.Contains(rr.Tag(i), "len"):
			// // todo no tags defined yet
			default:
				f := rr.Field(i).Name()
				switch x := rr.Field(i).Type().(type) {
				case *types.Array:
					switch x.Len() {
					case 2:
						generate.Uint16(b, f, i+1 == rr.NumFields())
					case 4:
						generate.Uint32(b, f, i+1 == rr.NumFields())
					}
				default:
					switch x.String() {
					case generate.Import + ".Name":
						generate.Name(b, f, i+1 == rr.NumFields())
					}
				}
			}
		}

		fmt.Fprintf(b, "return nil\n}\n")
	}
}
