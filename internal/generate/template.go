package generate

import "text/template"

// New returns a new template use for generating Go code.
func New(name, s string) *template.Template {
	return template.Must(template.New(name).Funcs(Funcs).Parse(s))
}
