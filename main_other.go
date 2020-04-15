// +build !windows

package main

import (
	"errors"
	"path/filepath"

	"github.com/urfave/cli/v2"
)

func registerAction(*cli.Context) error {
	return errors.New("Windows only")
}

func normalizePath(p string) (string, error) {
	return filepath.Abs(p)
}
