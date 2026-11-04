//go:build !windows

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "the desktop UI is only available on Windows; use the agent's status page at http://127.0.0.1:7878/")
	os.Exit(1)
}
