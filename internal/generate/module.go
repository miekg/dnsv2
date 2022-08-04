package generate

import (
	"fmt"
	"go/format"
	"go/types"
	"os"

	"golang.org/x/tools/go/packages"
)

const Import = "github.com/miekg/dnsv2"

// Load retrieves package description for a given module.
func Load() (*types.Package, error) {
	conf := packages.Config{Mode: packages.NeedTypes | packages.NeedTypesInfo}
	pkgs, err := packages.Load(&conf, Import)
	if err != nil {
		return nil, err
	}
	return pkgs[0].Types, nil
}

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
