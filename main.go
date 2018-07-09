package main

import (
	"flag"
	"os"

	execplugin "github.com/mrogers950/acme-exec-plugin/plugin"
	execplugincli "github.com/mrogers950/acme-exec-plugin/plugin/client"
)

func main() {
	o := &execplugin.PluginOptions{
		ServerURL:      "",
		ServerCA:       "",
		Debug:          false,
		ClientKeyPath:  "acme-plugin-clientkey.pem",
		WriteClientKey: false,
		CertPath:       "acme-plugin-cert.pem",
		CertKeyPath:    "acme-plugin-key.pem",
		ChallengeAddr:  "",
		DirPath:        "/dir",
		RegisterEmail:  "foo@bar.com",
		DebugFile:      "",
	}

	flag.StringVar(&o.ServerURL, "server-url", o.ServerURL, "An HTTPS ACME server URL. Required")
	flag.StringVar(&o.ServerCA, "server-ca", o.ServerCA, "ACME server CA for HTTPS. Uses the system CA store if unset")
	flag.StringVar(&o.ClientKeyPath, "client-key", o.ClientKeyPath, "The path to a PEM private key file for client registration. If the file does not exist, a generated key is saved when specifying --write-client-key")
	flag.BoolVar(&o.WriteClientKey, "write-client-key", o.WriteClientKey, "Write the client registration key to the --client-key file")
	flag.StringVar(&o.CertPath, "cert", o.CertPath, "The path to cache the fulfilled certificate. When the file does not exist, the issued certificate is saved. If the file exists, the plugin returns the cert as a cached credential. Must be specified with --cert-key")
	flag.StringVar(&o.CertKeyPath, "cert-key", o.CertKeyPath, "The path to cache the fulfilled certificate key. When the file does not exist, the issued certificate key is saved. If the file exists, the plugin returns the key as a cached credential. Must be specified with --cert")
	flag.StringVar(&o.ChallengeAddr, "challenge-addr", o.ChallengeAddr, "Address (with port) to listen for HTTP on for the client to satisfy ACME challenges")
	flag.BoolVar(&execplugincli.PrintDebug, "debug", o.Debug, "Print debug messages")
	flag.StringVar(&o.DebugFile, "debug-file", o.DebugFile, "Print debug messages to the specified file when using --debug")
	flag.StringVar(&o.DirPath, "directory-path", o.DirPath, "The path to the discovery directory on the ACME server")
	flag.StringVar(&o.RegisterEmail, "email", o.RegisterEmail, "The email address used for client registration")
	flag.StringVar(&o.Subject, "subject", o.Subject, "The subject name of the certificate to request. Required")
	flag.StringVar(&o.Names, "names", o.Names, "A comma separated list of additional names to request in the certificate")
	flag.Parse()
	os.Exit(execplugin.RunAcmeExecPlugin(o))
}
