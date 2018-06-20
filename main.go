package main

import (
	"flag"
	"os"

	execplugin "github.com/mrogers950/acme-exec-plugin/plugin"
)

func main() {
	o := &execplugin.PluginOptions{
		ServerURL:      "https://127.0.0.1:14000",                                                                      // pebble testing
		ServerCA:       "/home/mrogers/projects/pebble/src/github.com/letsencrypt/pebble/test/certs/pebble.minica.pem", // pebble testing
		WriteClientKey: true,
		ClientKeyPath:  "clientkey.pem",
		CertPath:       "cert.pem",
		ChallengeAddr:  "localhost:5002", // pebble testing
		DirPath:        "/dir",
		RegisterEmail:  "foo@bar.com",
	}

	flag.StringVar(&o.ServerURL, "server-url", o.ServerURL, "ACME server url")
	flag.StringVar(&o.ServerCA, "server-ca", o.ServerCA, "ACME server CA for HTTPS")
	flag.StringVar(&o.ClientKeyPath, "client-key-path", o.ClientKeyPath, "path to load client key from")
	flag.StringVar(&o.CertPath, "cert-path", o.CertPath, "path to save cert to")
	flag.StringVar(&o.ChallengeAddr, "challenge-addr", o.ChallengeAddr, "address to listen to for client challenge")
	flag.BoolVar(&o.WriteClientKey, "write-client-key", o.WriteClientKey, "write out client key to the client key path")
	flag.StringVar(&o.DirPath, "directory-path", o.DirPath, "acme directory path")
	flag.StringVar(&o.RegisterEmail, "email", o.RegisterEmail, "client registration email")
	flag.Parse()
	os.Exit(execplugin.RunAcmeExecPlugin(o))
}
