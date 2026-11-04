package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"remoteconfig/internal/server"
)

const keysUsage = `usage: server keys <command> [-data <db file>] [-signing-key <file>] [-passphrase-file <file>]

  show        print the key agents should pin (and the rotation chain, if any)
  rotate      make a new signing key current. Agents that trust the old key follow the new one
              automatically; the old private key is erased. Restart a running server afterwards.
  protect     encrypt the private key in the key file with a passphrase (or change the passphrase)
  unprotect   store the private key in the clear again

Passphrases are never taken from the command line, where other users could see them:
  the current one:  RC_SIGNING_PASSPHRASE, or -passphrase-file
  a new one:        RC_SIGNING_NEW_PASSPHRASE, or -new-passphrase-file   (protect only; 12+ characters)

The key file is signing.json beside the database unless -signing-key says otherwise.
Back it up separately from the database. Whoever holds an unencrypted copy can sign config and
commands that every agent will obey; an encrypted copy is useless without the passphrase.
`

// secret reads a passphrase from a file (trailing newline removed) or, failing that, the environment.
func secret(file, env string) (string, error) {
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return "", err
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	}
	return os.Getenv(env), nil
}

func keysCmd(args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "help" {
		fmt.Print(keysUsage)
		return 2
	}
	cmd := args[0]
	fs := flag.NewFlagSet("keys "+cmd, flag.ExitOnError)
	data := fs.String("data", "remoteconfig.db", "path of the SQLite database")
	keyFile := fs.String("signing-key", "", "signing key file")
	passFile := fs.String("passphrase-file", "", "file holding the key's current passphrase")
	newPassFile := fs.String("new-passphrase-file", "", "file holding the new passphrase (protect)")
	fs.Parse(args[1:])
	path := *keyFile
	if path == "" {
		path = filepath.Join(filepath.Dir(*data), "signing.json")
	}
	if _, err := os.Stat(path); err != nil && cmd != "show" {
		return fail("no signing key at %s (start the server once to create it)", path)
	}
	pass, err := secret(*passFile, "RC_SIGNING_PASSPHRASE")
	if err != nil {
		return fail("reading the passphrase: %v", err)
	}
	// "protect" on a plain file takes only the new passphrase; opening it with one would seal it
	// with the wrong one if they differ.
	open := pass
	sg, err := server.OpenSignerWith(path, open)
	if err != nil {
		return fail("%v", err)
	}
	defer sg.Close()

	switch cmd {
	case "show":
		ks := sg.KeySet()
		cur := sg.Current()
		state := "stored unencrypted"
		if sg.Protected() {
			state = "encrypted with a passphrase"
		}
		fmt.Printf("current key id: %s (%s)\npublic key (for -server-key):\n  %s\n", cur.KeyID, state, cur.Public)
		if len(ks.Keys) > 1 {
			fmt.Printf("\n%d keys in the chain (oldest first):\n", len(ks.Keys))
			for _, k := range ks.Keys {
				mark := ""
				if k.KeyID == ks.Current {
					mark = "  <- current"
				}
				fmt.Printf("  %s%s\n", k.KeyID, mark)
			}
		}
	case "rotate":
		old := sg.Current().KeyID
		kid, err := sg.Rotate()
		if err != nil {
			return fail("%v", err)
		}
		fmt.Printf("rotated: %s -> %s\nnew public key:\n  %s\nAgents that trust %s will follow the chain. New installs can pin the new key.\n", old, kid, sg.Current().Public, old)
	case "protect":
		newPass, err := secret(*newPassFile, "RC_SIGNING_NEW_PASSPHRASE")
		if err != nil {
			return fail("reading the new passphrase: %v", err)
		}
		if newPass == "" {
			newPass = pass // protecting with the passphrase the file already opens with is a no-op, but harmless
		}
		if newPass == "" {
			return fail("give the new passphrase in RC_SIGNING_NEW_PASSPHRASE or -new-passphrase-file")
		}
		if err := sg.Protect(newPass); err != nil {
			return fail("%v", err)
		}
		fmt.Printf("the signing key in %s is now encrypted.\nStart the server with RC_SIGNING_PASSPHRASE (or -signing-passphrase-file) set to the new passphrase.\nOld copies of the file, such as backups, still hold the unencrypted key: destroy them.\n", path)
	case "unprotect":
		if !sg.Protected() {
			return fail("the key in %s is not encrypted", path)
		}
		if err := sg.Unprotect(); err != nil {
			return fail("%v", err)
		}
		fmt.Printf("the signing key in %s is stored unencrypted again.\n", path)
	default:
		return fail("unknown command %q\n\n%s", cmd, keysUsage)
	}
	return 0
}
