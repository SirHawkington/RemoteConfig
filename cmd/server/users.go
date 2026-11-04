package main

import (
	"flag"
	"fmt"
	"os"
	"text/tabwriter"

	"remoteconfig/internal/server"
)

const userUsage = `usage: server user <command> [flags]

  list                          show accounts
  add     -username u [-name "Full Name"] [-password p] [-admin]
  passwd  -username u [-password p]      (signs the user out everywhere)
  admin   -username u [-off]             make or stop being a server administrator
  disable -username u                    (also revokes their tokens)
  enable  -username u
  delete  -username u
  grant   -username u -project p -role viewer|operator|admin
  revoke  -username u -project p

Every command takes -data <file> (default remoteconfig.db). They work on the database file
directly: no running server and no existing login are needed. A password left out is
generated and printed once. Prefer that to typing one on the command line.
`

func userCmd(args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "help" {
		fmt.Print(userUsage)
		return 2
	}
	cmd := args[0]
	fs := flag.NewFlagSet("user "+cmd, flag.ExitOnError)
	data := fs.String("data", "remoteconfig.db", "path of the SQLite database")
	username := fs.String("username", "", "account name")
	name := fs.String("name", "", "display name")
	password := fs.String("password", "", "password (generated if empty)")
	admin := fs.Bool("admin", false, "make a server administrator")
	off := fs.Bool("off", false, "with admin: take the flag away")
	project := fs.String("project", "", "project id")
	role := fs.String("role", "", "viewer, operator or admin")
	fs.Parse(args[1:])

	st, err := server.OpenStore(*data, "")
	if err != nil {
		return fail("opening %s: %v", *data, err)
	}
	defer st.Close()

	need := func(what string, v string) bool {
		if v == "" {
			fmt.Fprintf(os.Stderr, "error: -%s is required\n", what)
			return false
		}
		return true
	}

	switch cmd {
	case "list":
		users, err := st.Users()
		if err != nil {
			return fail("%v", err)
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "USERNAME\tNAME\tADMIN\tSTATE\tPASSWORD")
		for _, u := range users {
			state, pw := "active", "set"
			if u.Disabled {
				state = "disabled"
			}
			if !u.HasPassword {
				pw = "none (token only)"
			}
			fmt.Fprintf(tw, "%s\t%s\t%v\t%s\t%s\n", u.Username, u.DisplayName, u.IsAdmin, state, pw)
		}
		tw.Flush()
	case "add":
		if !need("username", *username) {
			return 2
		}
		generated := false
		if *password == "" {
			*password, generated = server.GeneratePassword(), true
		}
		u, err := st.CreateUser(*username, *name, *password, *admin)
		if err != nil {
			return fail("%v", err)
		}
		fmt.Printf("created %s (admin=%v)\n", u.Username, u.IsAdmin)
		if generated {
			fmt.Printf("password: %s   (shown once)\n", *password)
		}
	case "passwd":
		if !need("username", *username) {
			return 2
		}
		generated := false
		if *password == "" {
			*password, generated = server.GeneratePassword(), true
		}
		if err := st.UpdateUser(*username, server.UserPatch{Password: password}); err != nil {
			return fail("%v", err)
		}
		fmt.Printf("password changed for %s; they are signed out everywhere\n", *username)
		if generated {
			fmt.Printf("password: %s   (shown once)\n", *password)
		}
	case "admin":
		if !need("username", *username) {
			return 2
		}
		on := !*off
		if err := st.UpdateUser(*username, server.UserPatch{IsAdmin: &on}); err != nil {
			return fail("%v", err)
		}
		fmt.Printf("%s is now admin=%v\n", *username, on)
	case "disable", "enable":
		if !need("username", *username) {
			return 2
		}
		dis := cmd == "disable"
		if err := st.UpdateUser(*username, server.UserPatch{Disabled: &dis}); err != nil {
			return fail("%v", err)
		}
		fmt.Printf("%s: %sd\n", *username, cmd)
	case "delete":
		if !need("username", *username) {
			return 2
		}
		if err := st.DeleteUser(*username); err != nil {
			return fail("%v", err)
		}
		fmt.Printf("deleted %s\n", *username)
	case "grant", "revoke":
		if !need("username", *username) || !need("project", *project) {
			return 2
		}
		r := server.RoleNone
		if cmd == "grant" {
			var ok bool
			if r, ok = server.ParseRole(*role); !ok {
				fmt.Fprintln(os.Stderr, "error: -role must be viewer, operator or admin")
				return 2
			}
		}
		if err := st.SetProjectRole(*project, *username, r); err != nil {
			return fail("%v", err)
		}
		fmt.Printf("%s in %s: %s\n", *username, *project, r)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, userUsage)
		return 2
	}
	return 0
}

func fail(format string, a ...any) int {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", a...)
	return 1
}
