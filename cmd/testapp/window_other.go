//go:build !windows

package main

func runWindow() { logf("window: not supported on this platform") }
