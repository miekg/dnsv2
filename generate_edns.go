//go:build ignore

// See types_generate.go. This generator generates functions and maps for the edns0 types.

package main

import (
	"bytes"
	"log"

	"github.com/miekg/dnsv2/internal/generate"
)

var (
	// Interface implementation check for all RRs.
	iface = generate.New("iface", `
var (
{{range .}} _ Option = new({{. | ToUpper}})
{{end}}
)
`)

	// OptioncCode
	optionCode = generate.New("optionCode", `
// OptionCode returns the option code of the Option.
func OptionCode(e Option) Code {
	switch e.(type) {
{{range .}} case *{{. | ToUpper}}:
	return Code{{.}}
{{end}} }
	return CodeNone
}
`)

	// codeToOption
	codeToOption = generate.New("optionCode", `
var codeToOption = map[Code]func() Option{
{{range .}} Code{{.}}: func() Option { return new({{. | ToUpper}}) },
{{end}} }
`)
)

func main() {
	pkg, err := generate.Load()
	if err != nil {
		log.Fatal(err)
	}
	typex := generate.Types(pkg, "Code")

	b := &bytes.Buffer{}
	generate.Hdr(b, "edns")

	if err := optionCode.Execute(b, typex); err != nil {
		log.Fatal("failed to generate %s: %s", "optionCode", err)
	}
	if err := iface.Execute(b, typex); err != nil {
		log.Fatal("failed to generate %s: %s", "iface", err)
	}
	if err := codeToOption.Execute(b, typex); err != nil {
		log.Fatal("failed to generate %s: %s", "codeToOption", err)
	}

	if err := generate.SaveSource(b.Bytes(), "zedns.go"); err != nil {
		log.Printf("%s\n", b)
		log.Fatal("failed to save source: %s", err)
	}
}
