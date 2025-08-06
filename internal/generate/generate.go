// Package generate holds helper function for the code generation that we use.
package generate

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
)

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
							types = append(types, typeSpec.Name.Name)
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
