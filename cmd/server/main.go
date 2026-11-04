// Command server is the RemoteConfig server (placeholder name).
//
//	server [flags]                        run the server
//	server user list|add|passwd|...       manage dashboard accounts (see "server user -h")
//	server keys show|rotate               the key that signs config and commands
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"remoteconfig/internal/proto"
	"remoteconfig/internal/server"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "user" {
		os.Exit(userCmd(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "keys" {
		os.Exit(keysCmd(os.Args[2:]))
	}

	addr := flag.String("addr", ":8080", "listen address")
	data := flag.String("data", "remoteconfig.db", "path of the SQLite database (empty = in-memory, lost on exit)")
	adminToken := flag.String("admin-token", os.Getenv("RC_ADMIN_TOKEN"), "keep a token for the \"admin\" account (for scripts that used the old shared admin token); stored hashed")
	adminPassword := flag.String("admin-password", os.Getenv("RC_ADMIN_PASSWORD"), "password for the \"admin\" account when it has none (generated and printed if empty)")
	signingKey := flag.String("signing-key", "", "path of the signing key file (default: signing.json beside the database)")
	signingPassFile := flag.String("signing-passphrase-file", "", "file holding the passphrase that encrypts the signing key (or set RC_SIGNING_PASSPHRASE). An unencrypted key is encrypted on first start")
	tlsCert := flag.String("tls-cert", "", "TLS certificate file (serve HTTPS)")
	tlsKey := flag.String("tls-key", "", "TLS private key file")
	artifacts := flag.String("artifacts", "", "directory for uploaded screenshots and files (default: \"artifacts\" next to the database)")
	interval := flag.Duration("checkin-interval", 5*time.Minute, "check-in interval handed to agents")
	seed := flag.Bool("dev-seed", false, "create a demo project, sample global config and print an enrollment token")
	flag.Parse()

	st, err := server.OpenStore(*data, *adminToken)
	if err != nil {
		log.Fatal(err)
	}
	if *artifacts != "" {
		if err := st.SetArtifactDir(*artifacts); err != nil {
			log.Fatal(err)
		}
	}
	if pass, err := secret(*signingPassFile, "RC_SIGNING_PASSPHRASE"); err != nil {
		log.Fatalf("reading the signing key passphrase: %v", err)
	} else {
		st.SetSigningPassphrase(pass)
	}
	if *signingKey != "" {
		if err := st.SetSigningKeyPath(*signingKey); err != nil {
			log.Fatal(err)
		}
	}
	sg, err := st.Signer()
	if err != nil {
		log.Fatalf("signing key: %v", err)
	}
	cur := sg.Current()
	log.Printf("config and commands are signed with key %s. Pin it on agents with: -server-key %s", cur.KeyID, cur.Public)
	switch {
	case sg.Migrated():
		log.Printf("the signing key was stored in the clear and is now encrypted with your passphrase. Destroy old copies of signing.json (backups included): they still hold the unencrypted key")
	case sg.Protected():
		log.Printf("the signing key is encrypted at rest")
	case *data != "":
		log.Printf("WARNING: the signing key is stored unencrypted in %s: anyone who can read that file can sign commands for every agent. Set RC_SIGNING_PASSPHRASE (12+ characters) to encrypt it", "signing.json beside the database")
	}
	// First run: make sure somebody can sign in.
	if pw, err := st.EnsureAdminLogin(*adminPassword); err != nil {
		log.Fatal(err)
	} else if pw != "" {
		fmt.Printf("\nFirst-run administrator account created.\n  username: admin\n  password: %s\nSign in to the dashboard with it and change it (account menu), or run `server user passwd`.\n\n", pw)
	}
	if *seed {
		devSeed(st)
	}

	go func() { // expire old metrics, sessions and spent enrollment tokens
		for range time.Tick(6 * time.Hour) {
			st.Prune()
		}
	}()

	secure := *tlsCert != "" && *tlsKey != ""
	if !secure && !isLoopback(*addr) {
		log.Printf("WARNING: listening on %s without TLS: dashboard passwords and session tokens travel in clear text. "+
			"Use -tls-cert/-tls-key, or put the server behind an HTTPS reverse proxy.", *addr)
	}
	srv := server.New(st, server.Options{CheckinInterval: *interval})
	log.Printf("listening on %s (check-in interval %s)", *addr, *interval)
	if secure {
		log.Fatal(http.ListenAndServeTLS(*addr, *tlsCert, *tlsKey, srv.Handler()))
	}
	log.Fatal(http.ListenAndServe(*addr, srv.Handler()))
}

func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// devSeed makes first-run testing painless: a "demo" project with a sample config
// and a fresh enrollment token.
func devSeed(st *server.Store) {
	st.Seed("demo", "Demo", &proto.ConfigDocument{
		Data: map[string]any{
			"language":      "en",
			"attractLoopS":  45,
			"volume":        0.8,
			"showDebugInfo": false,
		},
		ReloadMode: "watch",
	})
	tok := st.NewEnrollToken("demo", nil, 72*time.Hour)
	fmt.Printf("demo project ready. enrollment token: %s\n", tok)
}
