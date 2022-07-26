//go:build ignore

// See types_generate.go. This generator generates the String() methods the RRs.

package main

import (
	"bytes"
	"fmt"
	"go/types"
	"log"
	"strings"

	"github.com/miekg/dnsv2/internal/generate"
)

func main() {
	pkg, err := generate.Load()
	if err != nil {
		log.Fatal(err)
	}

	b := &bytes.Buffer{}
	generate.Hdr(b, "strings", []string{"strconv", "encoding/binary"})
	String(b, pkg)

	if err := generate.SaveSource(b.Bytes(), "zstring.go"); err != nil {
		log.Printf("%s\n", b)
		log.Fatal("failed to save source: %s", err)
	}
}

// Generate the String() methods.
func String(b *bytes.Buffer, pkg *types.Package) {
	typex := generate.Types(pkg, "Type")
	scope := pkg.Scope()

Types:
	for _, name := range typex {
		o := scope.Lookup(name)
		rr := generate.RR(o.Type(), scope)
		if rr == nil {
			continue
		}

		// check if this type doesn't need a String() method to be generated.
		for i := 1; i < rr.NumFields(); i++ {
			if strings.Contains(rr.Tag(i), "-string") {
				continue Types
			}
		}

		fmt.Fprintf(b, "func (rr *%s) String() string {\n", name)

		fields := []string{}
		for i := 1; i < rr.NumFields(); i++ {
			switch {
			// case strings.Contains(rr.Tag(i), "len"):
			// // no tags defined yet
			default:
				f := rr.Field(i).Name()
				switch x := rr.Field(i).Type().(type) {
				case *types.Array:
					expr := ""
					switch x.Len() {
					case 2:

						fmt.Fprintf(b, "xxx%d := binary.BigEndian.Uint16(rr.%s[:])\n", i, f)

						expr = fmt.Sprintf("strconv.FormatUint(uint64(%s%d), 10)", "xxx", i)
					case 4:

						fmt.Fprintf(b, "xxx%d := binary.BigEndian.Uint32(rr.%s[:])\n", i, f)

						expr = fmt.Sprintf("strconv.FormatUint(uint64(%s%d), 10)", "xxx", i)
					}
					fields = append(fields, expr)
				default:
					switch x.String() {
					case generate.Import + ".Name":
						fields = append(fields, fmt.Sprintf("rr.%s.String()", f))
					}
				}
			}
		}

		fmt.Fprintf(b, "\treturn Type%s.String()", name)

		if len(fields) > 0 {
			fmt.Fprintf(b, "+ \"\\t\" + %s", strings.Join(fields, "+ \" \" +"))
		}
		fmt.Fprintf(b, "\n}\n")
	}
}
