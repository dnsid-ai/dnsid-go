//go:build !unix && !windows

package foundry

import (
	"fmt"
	"os"
)

func unsupportedFilesystem() error {
	return failure(UnsupportedContract, nil, fmt.Errorf("foundry: durable file locking is unsupported on this platform; inject a FoundryStore"))
}
func tryFileLock(*os.File) (bool, error)     { return false, unsupportedFilesystem() }
func unlockFile(*os.File) error              { return unsupportedFilesystem() }
func replaceFile(string, string) error       { return unsupportedFilesystem() }
func makeDirectories(string) error           { return unsupportedFilesystem() }
func restrictPrivate(string) error           { return unsupportedFilesystem() }
func checkPrivate(string, os.FileInfo) error { return unsupportedFilesystem() }
