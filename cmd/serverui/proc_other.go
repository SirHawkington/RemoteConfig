//go:build !windows

package main

import (
	"os"
	"os/exec"
)

func prepare(*exec.Cmd) {}
func adopt(*os.Process) {}
