//go:build windows

package agent

import (
	"crypto/sha1"
	"encoding/hex"
	"strings"

	"golang.org/x/sys/windows"
)

// AcquireSingleInstance takes a machine-wide named mutex derived from key (the state
// directory). It returns ok=false if another agent already holds it. The mutex is
// released by the OS when the process exits, however it exits.
func AcquireSingleInstance(key string) (ok bool, err error) {
	sum := sha1.Sum([]byte(strings.ToLower(key)))
	name, err := windows.UTF16PtrFromString(`Global\RemoteConfigAgent-` + hex.EncodeToString(sum[:6]))
	if err != nil {
		return false, err
	}
	_, err = windows.CreateMutex(nil, false, name)
	if err == windows.ERROR_ALREADY_EXISTS {
		return false, nil
	}
	return err == nil, err
}
