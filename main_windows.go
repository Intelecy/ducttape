package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/urfave/cli/v2"

	"golang.org/x/sys/windows/registry"
)

const (
	regkey = `Software\Caphyon\Advanced Installer\Settings`
)

func registerAction(c *cli.Context) error {
	ex, err := os.Executable()
	if err != nil {
		return err
	}

	ex, err = filepath.Abs(ex)
	if err != nil {
		return err
	}

	logInfo(`setting 'HKCU\%s\SignTool Path' to %s`, regkey, ex)

	k, _, err := registry.CreateKey(registry.CURRENT_USER, regkey, registry.ALL_ACCESS)
	if err != nil {
		return err
	}
	defer k.Close()

	return k.SetStringValue("SignTool Path", ex)
}

// stackoverflow ftw
func normalizePath(p string) (string, error) {
	if p == "" {
		return "", fmt.Errorf("path empty")
	}
	p, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	// Is this _really_ an absolute path?
	if !strings.HasPrefix(p, "\\\\") {
		// It's a drive: path!
		// Return a UNC path.
		p = "\\\\%3F\\" + p
	}

	// This will return file:////?/c:/foobar
	//
	// Why? Because:
	//  1. Go will choke on file://c:/ because the "domain" includes a :.
	//  2. Windows will choke on file:///c:/ because the path will be
	//     /c:/... which is _relative_ to the current drive.
	//
	// This path (a) has no "domain" and (b) starts with a slash. Yay!
	return "file://" + filepath.ToSlash(p), nil
}
