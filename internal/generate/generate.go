// Package generate holds helper function for the code generation that we use.
package generate

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"log"
	"os"
	"reflect"
	"slices"
)

var exclude = []string{"APLPrefix", "RFC3597"}

var FlagDebug = flag.Bool("debug", false, "Emit the non-formatted code to standard output and do not write it to a file.")

// Types returns all types names from the file that are exported.
func Types(file string) ([]string, error) {
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, file, nil, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s: %v", file, err)
	}

	types := []string{}
	for _, decl := range node.Decls {
		declType := reflect.TypeOf(decl)

		if declType.String() == "*ast.GenDecl" {
			genDecl := decl.(*ast.GenDecl)
			if genDecl.Tok == token.TYPE {
				for _, spec := range genDecl.Specs {
					if typeSpec, ok := spec.(*ast.TypeSpec); ok {
						if typeSpec.Name.IsExported() {
							if !slices.Contains(exclude, typeSpec.Name.Name) {
								types = append(types, typeSpec.Name.Name)
							}
						}
					}
				}
			}
		}
	}
	return types, nil
}

// Fields returns the export type names and the field's names. Each name is prefixed with "rr.".
func Fields(file string) (map[string][]string, error) {
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, file, nil, parser.AllErrors|parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}

	types := map[string][]string{}
	for _, decl := range node.Decls {
		declType := reflect.TypeOf(decl)

		if declType.String() == "*ast.GenDecl" {
			genDecl := decl.(*ast.GenDecl)
			if genDecl.Tok == token.TYPE {
				for _, spec := range genDecl.Specs {
					if typeSpec, ok := spec.(*ast.TypeSpec); ok {
						if typeSpec.Name.IsExported() {
							types[typeSpec.Name.Name] = fields(typeSpec.Type)
						}
					}
				}
			}
		}
	}
	return types, nil
}

func fields(node ast.Node) []string {
	fields := []string{}
	switch n := node.(type) {
	case *ast.StructType:
		for _, field := range n.Fields.List {
			for _, f := range field.Names {
				if f.String() == "Hdr" {
					continue
				}
				fields = append(fields, "rr."+f.String())
			}
		}
	}
	return fields
}

// StructTypeSpecs returns the struct types from file that can be inspected for the struct tags.
func StructTypeSpecs(file string) ([]*ast.TypeSpec, error) {
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, file, nil, parser.AllErrors|parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	structs := []*ast.TypeSpec{}

	ast.Inspect(node, func(n ast.Node) bool {
		typeSpec, ok := n.(*ast.TypeSpec)
		if !ok {
			return true
		}

		if _, ok := typeSpec.Type.(*ast.StructType); !ok {
			return true
		}

		if !typeSpec.Name.IsExported() {
			return true
		}

		structs = append(structs, typeSpec)
		return true
	})
	return structs, nil
}

func Write(b *bytes.Buffer, out string) {
	formatted, err := format.Source(b.Bytes())
	if err != nil {
		b.WriteTo(os.Stderr)
		log.Fatalf("Failed to generate %s: %v", out, err)
	}

	if *FlagDebug {
		fmt.Print(string(formatted))
		return
	}

	if err := os.WriteFile(out, formatted, 0640); err != nil {
		log.Fatalf("Failed to generate %s: %v", out, err)
	}
}
