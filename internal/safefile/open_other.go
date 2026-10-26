//go:build !unix

package safefile

import "os"

func open(path string) (*os.File, error) { return os.Open(path) }
