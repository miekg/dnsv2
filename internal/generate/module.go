package generate

import (
	"fmt"
	"go/format"
	"go/types"
	"html/template"
	"os"
	"strings"

	"golang.org/x/tools/go/packages"
)

// Import is our package name.
const Import = "github.com/miekg/dnsv2"

// Funcs are default funcs we use in the templates.
var Funcs = template.FuncMap{
	"ToUpper": strings.ToUpper,
}

// Load retrieves package description for a given module.
func Load() (*types.Package, error) {
	conf := packages.Config{Mode: packages.NeedTypes | packages.NeedTypesInfo}
	pkgs, err := packages.Load(&conf, Import)
	if err != nil {
		return nil, err
	}
	return pkgs[0].Types, nil
}

// SaveSource formats the source in buf and saves it into filename. Filename should start with a 'z'.
func SaveSource(buf []byte, filename string) error {
	// gofmt
	res, err := format.Source(buf)
	if err != nil {
		return fmt.Errorf("failed to format source for %s: %w", filename, err)
	}

	// write
	f, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to save source for %s: %w", filename, err)
	}
	f.Write(res)
	return f.Close()
}

// Types returns the types that share the prefix, prefix<None> is always excluded.
func Types(pkg *types.Package, prefix string) []string {
	scope := pkg.Scope()
	var typex []string
	for _, name := range scope.Names() {
		o := scope.Lookup(name)
		if o == nil || !o.Exported() {
			continue
		}
		if !strings.HasPrefix(o.Name(), prefix) {
			continue
		}
		name := strings.TrimPrefix(o.Name(), prefix)
		if name == "" || name == "None" {
			continue
		}
		if o.Type().String() != Import+"."+prefix {
			continue
		}
		typex = append(typex, name)
	}
	return typex
}

// RR will take a type and the package scope, and return the (innermost) struct if the type is considered a RR type
func RR(t types.Type, scope *types.Scope) *types.Struct {
	st, ok := t.Underlying().(*types.Struct)
	if !ok {
		return nil
	}
	if st.NumFields() == 0 {
		return nil
	}
	if st.Field(0).Type() == scope.Lookup("Header").Type() {
		return st
	}
	return nil
}
