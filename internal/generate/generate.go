// Package generate holds helper function for the code generation that we use.
package generate

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"unicode"
	"unicode/utf8"
)

// ExportedTypes returns all types from the file that are exported.
func ExportedTypes(file string) ([]string, error) {
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
						rn, _ := utf8.DecodeRuneInString(typeSpec.Name.Name)
						if unicode.IsUpper(rn) {
							types = append(types, typeSpec.Name.Name)
						}
					}
				}
			}
		}
	}
	return types, nil
}
