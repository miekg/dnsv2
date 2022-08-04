//+build ignore

// See types_generate.go. This generator generates functions and maps for the edns0 types.

package main

import (
	"bytes"
	"log"
	"strings"
	"text/template"

	"github.com/miekg/dnsv2/internal/generate"
)

var hdr = `
// Code generated by "go run edns_generate.go"; Edits will be lost.

package dns

`
var funcs = template.FuncMap{
	"ToUpper": strings.ToUpper,
}

var (
	// Interface implementation check for all RRs.
	iface = template.Must(template.New("iface").Funcs(funcs).Parse(`
var (
{{range .}} _ Option = new({{. | ToUpper}})
{{end}}
)
`))

	// OptioncCode
	optionCode = template.Must(template.New("optionCode").Funcs(funcs).Parse(`
// OptionCode returns the option code of the Option.
func OptionCode(e Option) Code {
	switch e.(type) {
{{range .}} case *{{. | ToUpper}}:
	return Code{{.}}
{{end}} }
	return CodeNone
}
`))

	// codeToOption
	codeToOption = template.Must(template.New("optionCode").Funcs(funcs).Parse(`
var codeToOption = map[Code]func() Option{
{{range .}} Code{{.}}: func() Option { return new({{. | ToUpper}}) },
{{end}} }
`))
)

func main() {
	pkg, err := generate.Load()
	if err != nil {
		log.Fatal(err)
	}
	typex := generate.Types(pkg, "Code")

	b := &bytes.Buffer{}
	b.WriteString(hdr)

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
		log.Fatal("failed go save source: %s", err)
	}
}
