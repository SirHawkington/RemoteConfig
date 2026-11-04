// Command rcctl drives a RemoteConfig server from a terminal or a build script: upload a script
// or a release, send it to devices in stages, and follow the rollout.
//
//	rcctl devices
//	rcctl script add|list|run ...
//	rcctl release upload|list|send ...
//	rcctl rollout list|show|halt|watch ...
//
// The server address and an API token (made in the dashboard's account menu) come from the
// environment, so a token never appears in a process list or a shell history.
package main

import (
	"fmt"
	"io"
	"os"
)

func main() {
	os.Exit(run(os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}

const usage = `usage: rcctl <command> [flags]

Set RCCTL_SERVER (e.g. https://rc.example.com) and RCCTL_TOKEN (an API token from the dashboard's
account menu, or RCCTL_TOKEN_FILE). RCCTL_PROJECT picks the project when you have more than one.

  devices                          list the project's devices
  script list                      list the script library
  script add <name> <file>         upload a script (a new version of <name>)
  script run <name> [devices]      run a script on devices, in stages by default
  release list                     list releases
  release upload <file>            upload an app (zip) or agent (executable) build
  release send <name@version|id>   install a release on devices, in stages by default
  rollout list | show <id>         see rollouts and each device's progress
  rollout halt <id>                stop sending to the devices not yet told
  rollout watch <id>               follow a rollout until it finishes (exit 1 if it halts)

Choose devices with -devices a,b (names or ids), -tag lobby, or -all. Run "rcctl <command> -h" for flags.
`

func run(args []string, getenv func(string) string, out, errOut io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "help" || args[0] == "--help" {
		fmt.Fprint(out, usage)
		return 0
	}
	c, err := newClient(getenv, out, errOut)
	if err != nil {
		fmt.Fprintln(errOut, "error:", err)
		return 2
	}
	var code int
	switch args[0] {
	case "devices":
		code = c.devices(args[1:])
	case "script":
		code = c.script(args[1:])
	case "release":
		code = c.release(args[1:])
	case "rollout":
		code = c.rollout(args[1:])
	default:
		fmt.Fprintf(errOut, "unknown command %q\n\n%s", args[0], usage)
		return 2
	}
	return code
}
