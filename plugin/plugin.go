package plugin

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/url"

	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"os"

	acmeclient "github.com/mrogers950/kubernetes-acme-exec-plugin/plugin/client"
)

func RunAcmeExecPlugin(o *PluginOptions) int {
	if err := o.Verify(); err != nil {
		fmt.Printf("error: %v\n", err)
		return 1
	}

	var roots *x509.CertPool
	if len(o.ServerCA) > 0 {
		cafile, err := ioutil.ReadFile(o.ServerCA)
		if err != nil {
			fmt.Printf("Cannot open server CAfile %s: %v\n", o.ServerCA, err)
			return 1
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(cafile) {
			fmt.Printf("Cannot add CAfile to pool\n")
			return 1
		}
	}

	var clientKey *rsa.PrivateKey
	if len(o.ClientKeyPath) > 0 {
		if _, err := os.Stat(o.ClientKeyPath); os.IsNotExist(err) {
			// generate a new client key
			clientKey, err = rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				fmt.Printf("Cannot generate client key: %v\n", err)
				return 1
			}
			if o.WriteClientKey {
				keyOut, err := os.OpenFile(o.ClientKeyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
				defer keyOut.Close()
				if err != nil {
					fmt.Printf("Cannot open key file for writing: %v\n", err)
					return 1
				}
				pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientKey)})
				fmt.Printf("wrote client key to %s\n", o.ClientKeyPath)
			}
		} else {
			// load client key
			keyFile, err := ioutil.ReadFile(o.ClientKeyPath)
			if err != nil {
				fmt.Printf("Cannot open client key file: %v\n", err)
				return 1
			}
			b, _ := pem.Decode(keyFile)
			clientKey, err = x509.ParsePKCS1PrivateKey(b.Bytes)
			if err != nil {
				fmt.Printf("Cannot parse client key file: %v\n", err)
				return 1
			}
		}
	}
	//tlsConf := &tls.Config{
	//	RootCAs: roots,
	//}
	//tr := &http.Transport{TLSClientConfig: tlsConf}
	//client := &http.Client{Transport: tr}
	//acmeClient := &acme.Client{
	//	DirectoryURL: o.ServerURL + "/dir",
	//	HTTPClient:   client,
	//	Key:          clientKey,
	//}
	//
	//ctx := context.Background()
	//disc, err := acmeClient.Discover(ctx)
	//if err != nil {
	//	fmt.Printf("Error discovering acme directory: %v\n", err)
	//}
	//
	//fmt.Printf("discovery info %v\n", disc)
	//_, err = acmeClient.Register(ctx, nil, acme.AcceptTOS)
	//if err != nil {
	//	fmt.Printf("Error registering account: %v", err)
	//	return 1
	//}

	cli, err := acmeclient.NewClient(o.ServerURL+"/dir", "foo@bar.com", clientKey, roots)
	if err != nil {
		fmt.Printf("Error getting new client %v\n", err)
	}

	err = acmeclient.NewRepl(cli)
	if err != nil {
		fmt.Printf("Error during reply %v\n", err)
	}

	return 0
}

type PluginOptions struct {
	ServerURL      string
	ServerCA       string
	ClientKeyPath  string
	WriteClientKey bool
}

func (o *PluginOptions) Verify() error {
	if len(o.ServerURL) < 1 {
		return fmt.Errorf("ACME server url is required")
	}
	serverUrl, err := url.Parse(o.ServerURL)
	if err != nil {
		return err
	}
	if serverUrl.Scheme != "https" {
		return fmt.Errorf("ACME requires HTTPS")
	}
	return nil
}
