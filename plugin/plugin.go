package plugin

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"

	"crypto/tls"

	"strings"

	acmeclient "github.com/mrogers950/acme-exec-plugin/plugin/client"
)

func RunAcmeExecPlugin(o *PluginOptions) int {
	if err := o.Verify(); err != nil {
		fmt.Printf("Error verifying options: %v\n", err)
		return 1
	}

	// If the certificate and key files exist, use them as cache so the plugin does not request a new cert each time.
	certOut, certOpenErr := os.OpenFile(o.CertPath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	defer certOut.Close()
	if certOpenErr != nil && !os.IsExist(certOpenErr) {
		fmt.Printf("Cannot open cert file for writing: %v\n", certOpenErr)
		return 1
	}
	keyOut, keyOpenErr := os.OpenFile(o.CertKeyPath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	defer keyOut.Close()
	if keyOpenErr != nil && !os.IsExist(keyOpenErr) {
		fmt.Printf("Cannot open cert key file for writing: %v\n", keyOpenErr)
		return 1
	}

	// The files exist, use them
	if os.IsExist(certOpenErr) && os.IsExist(keyOpenErr) {
		cert, err := ioutil.ReadFile(o.CertPath)
		if err != nil {
			fmt.Printf("error reading cert: %v\n", err)
			return 1
		}
		key, err := ioutil.ReadFile(o.CertKeyPath)
		if err != nil {
			fmt.Printf("error reading key: %v\n", err)
		}

		if len(cert) > 0 && len(key) > 0 {
			_, err := tls.X509KeyPair(cert, key)
			if err != nil {
				fmt.Printf("failed parsing client key/certificate: %v\n", err)
				return 1
			}
			creds := acmeclient.MakeCreds(cert, key)
			if creds == nil {
				fmt.Printf("failed to format output credentials\n")
				return 1
			}
			fmt.Printf("%s", string(creds))
			return 0
		}
	}

	var roots *x509.CertPool
	if len(o.ServerCA) > 0 {
		cafile, err := ioutil.ReadFile(o.ServerCA)
		if err != nil {
			fmt.Printf("Error opening server CA cert file %s: %v\n", o.ServerCA, err)
			return 1
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(cafile) {
			fmt.Printf("Cannot add CA file to pool\n")
			return 1
		}
	}

	var clientKey *rsa.PrivateKey
	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("Cannot generate client key: %v\n", err)
		return 1
	}
	if len(o.ClientKeyPath) > 0 {
		if _, err := os.Stat(o.ClientKeyPath); os.IsNotExist(err) {
			if o.WriteClientKey {
				keyOut, err := os.OpenFile(o.ClientKeyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
				defer keyOut.Close()
				if err != nil {
					fmt.Printf("Cannot open key file for writing: %v\n", err)
					return 1
				}
				pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientKey)})
			}
		} else {
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

	// register client
	cli, err := acmeclient.NewClient(o.ServerURL+o.DirPath, o.RegisterEmail, clientKey, roots, o.DebugFile)
	if err != nil {
		fmt.Printf("Error getting new client: %v\n", err)
		return 1
	}
	defer cli.Cleanup()

	// submit new order
	err = cli.Order()
	if err != nil {
		fmt.Printf("Error during order: %v\n", err)
		return 1
	}

	// get challenge information
	err = cli.GetChallenges()
	if err != nil {
		fmt.Printf("Error getting challenge tokens: %v\n", err)
		return 1
	}

	// set up challenge
	srv, err := cli.SetupChallenge(o.ChallengeAddr)
	if err != nil {
		fmt.Printf("Error setting up challenge server: %v\n", err)
	}
	defer srv.Close()

	// tell server to verify challenge
	err = cli.SendTryChallenge()
	if err != nil {
		fmt.Printf("Error sending 'try challenge' to server: %v\n", err)
		return 1
	}

	err = cli.PollForValidChallenge()
	if err != nil {
		fmt.Printf("Error polling for a valid challenge response: %v\n", err)
		return 1
	}

	err = cli.Finalize(o.Subject, o.SplitNames)
	if err != nil {
		fmt.Printf("Error finalizing order: %v\n", err)
		return 1
	}

	certUrl, err := cli.PollForOrderReady()
	if err != nil {
		fmt.Printf("Error polling for ready order: %v\n", err)
		return 1
	}

	creds, certPem, keyPem, err := cli.PollForCertificate(certUrl)
	if err != nil {
		fmt.Printf("Error fetching certificate: %v\n", err)
		return 1
	}

	fmt.Printf("%s", string(creds))
	certOut.Write(certPem)
	keyOut.Write(keyPem)
	return 0
}

type PluginOptions struct {
	ServerURL      string
	ServerCA       string
	ClientKeyPath  string
	CertPath       string
	CertKeyPath    string
	WriteClientKey bool
	Debug          bool
	DebugFile      string
	ChallengeAddr  string
	DirPath        string
	RegisterEmail  string
	Subject        string
	Names          string
	SplitNames     []string
}

func (o *PluginOptions) Verify() error {
	if len(o.ServerURL) == 0 {
		return fmt.Errorf("ACME server url is required")
	}
	serverUrl, err := url.Parse(o.ServerURL)
	if err != nil {
		return err
	}
	if serverUrl.Scheme != "https" {
		return fmt.Errorf("ACME requires HTTPS")
	}

	if len(o.Subject) == 0 {
		return fmt.Errorf("Certificate subject name is required")
	}

	if !strings.Contains(o.Subject, "CN") && !strings.Contains(o.Subject, "cn") {
		return fmt.Errorf("Certificate subject requires a CN")
	}

	if len(o.Names) != 0 {
		o.SplitNames = strings.Split(o.Names, ",")
	}

	return nil
}
