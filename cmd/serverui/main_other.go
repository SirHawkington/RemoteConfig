//go:build !windows

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "the server window is only available on Windows; run the server binary directly")
	os.Exit(1)
}
