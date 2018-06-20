package client

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"time"

	"golang.org/x/crypto/acme"
	"gopkg.in/square/go-jose.v2"
	"k8s.io/apimachinery/pkg/util/wait"
)

const (
	version       = "0.1"
	userAgentBase = "acme-exec-plugin"
	locale        = "en-us"
)

func userAgent() string {
	return fmt.Sprintf(
		"%s %s (%s; %s)",
		userAgentBase, version, runtime.GOOS, runtime.GOARCH)
}

type client struct {
	server            *url.URL
	directory         map[string]interface{}
	email             string
	acctID            string
	http              *http.Client
	privKey           jose.SigningKey
	nonce             string
	orderResponse     *OrderResponse
	orderLocation     string
	challengeResponse *ChallengeResponse
}

// registration and some other routines copied from the pebble client.

func NewClient(server, email string, key *rsa.PrivateKey, pebbleCAPool *x509.CertPool) (*client, error) {
	url, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	var privKey *rsa.PrivateKey
	if key != nil {
		privKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
	} else {
		privKey = key
	}

	c := &client{
		server: url,
		email:  email,
		http: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: pebbleCAPool,
				},
			},
		},
		privKey: jose.SigningKey{
			Key:       privKey,
			Algorithm: jose.RS256,
		},
	}

	err = c.updateDirectory()
	if err != nil {
		return nil, err
	}

	err = c.updateNonce()
	if err != nil {
		return nil, err
	}

	err = c.register()
	if err != nil {
		return nil, err
	}

	return c, nil
}

type OrderIdentifier struct {
	IdType  string `json:"type"`
	IdValue string `json:"value"`
}

type OrderResponse struct {
	Status         string
	Expires        string
	Identifiers    []OrderIdentifier
	Finalize       string
	Authorizations []string
	Certificate    string
}

func (c *client) Order() error {
	if orderURL, ok := c.directory["newOrder"]; !ok || orderURL.(string) == "" {
		return fmt.Errorf("missing \"newOrder\" entry in server directory")
	}
	orderURL := c.directory["newOrder"].(string)
	fmt.Printf("posting new order with %q\n", orderURL)

	// pebble requires a dns order type
	reqBody := struct {
		Identifiers []OrderIdentifier `json:"identifiers"`
	}{
		Identifiers: []OrderIdentifier{
			{
				IdType:  "dns",
				IdValue: "localhost",
			},
		},
	}

	reqBodyStr, err := json.Marshal(&reqBody)
	if err != nil {
		return err
	}

	respBody, resp, err := c.postAPIWithNonceRetry(orderURL, reqBodyStr, false)
	if err != nil {
		return err
	}

	locHeader := resp.Header.Get("Location")
	if locHeader == "" {
		return fmt.Errorf("no 'location' header in response")
	}
	c.orderLocation = locHeader

	c.orderResponse = &OrderResponse{}
	err = json.Unmarshal(respBody, c.orderResponse)
	if err != nil {
		return err
	}

	return nil
}

type ChallengeInfo struct {
	ChallengeType   string `json:"type"`
	ChallengeUrl    string `json:"url"`
	ChallengeToken  string `json:"token"`
	ChallengeStatus string `json:"status"`
}

type ChallengeResponse struct {
	Status     string          `json:"status"`
	Identifier OrderIdentifier `json:"identifier"`
	Challenges []ChallengeInfo `json:"challenges"`
	Expires    string          `json:"expires"`
}

func (c *client) GetChallenges() error {
	if c.orderResponse == nil {
		return fmt.Errorf("order has not been requested")
	}

	body, _, err := c.getAPI(c.orderResponse.Authorizations[0])
	if err != nil {
		return err
	}

	c.challengeResponse = &ChallengeResponse{}
	err = json.Unmarshal(body, c.challengeResponse)
	if err != nil {
		return err
	}

	return nil
}

func (c *client) PollForValidChallenge() error {
	return wait.Poll(time.Second, 40*time.Second, func() (done bool, err error) {
		fmt.Println("checking if server responds with validated challenge")
		chal, err := c.getHttpChallenge()
		if err != nil {
			return false, err
		}

		body, resp, err := c.getAPI(chal.ChallengeUrl)
		if err != nil {
			if resp != nil && resp.StatusCode/100 != 2 {
				return false, nil
			}
			return false, err
		}
		challengeInfo := &ChallengeInfo{}
		err = json.Unmarshal(body, challengeInfo)
		if err != nil {
			return false, err
		}

		fmt.Printf("challenge status: %s\n", challengeInfo.ChallengeStatus)
		return challengeInfo.ChallengeStatus == "valid", nil
	})
}

func (c *client) PollForCertificate(url string) ([]byte, error) {
	if len(url) < 1 {
		return nil, fmt.Errorf("no certificate url provided")
	}

	var certData []byte
	err := wait.Poll(time.Second, 10*time.Second, func() (done bool, err error) {
		fmt.Println("cert poll: pollfunc checking for a cert")
		body, resp, err := c.getAPI(url)
		if err != nil {
			if resp != nil && resp.StatusCode/100 != 2 {
				fmt.Println("cert poll: pollfunc retrying")
				return false, nil
			}
			fmt.Println("cert poll: pollfunc error")
			return false, err
		}
		certData = body
		fmt.Println("cert poll: returning pollfunc ok")
		return true, nil
	})

	if err != nil {
		fmt.Println("cert poll: returning err")
		return nil, err
	}
	fmt.Println("cert poll: returning Poll")

	return certData, nil
}

func (c *client) PollForOrderReady() (string, error) {
	var certUrl string

	err := wait.Poll(time.Second, 10*time.Second, func() (done bool, err error) {
		fmt.Println("order poll: checking for order ok")

		body, resp, err := c.getAPI(c.orderLocation)
		if err != nil {
			if resp != nil && resp.StatusCode/100 != 2 {
				fmt.Println("order poll: pollfunc retrying")
				return false, nil
			}
			fmt.Println("order poll: error")
			return false, err
		}
		orderResponse := &OrderResponse{}

		err = json.Unmarshal(body, orderResponse)
		if err != nil {
			return false, err
		}

		fmt.Printf("order poll: response %v\n", orderResponse)
		if orderResponse.Status != "valid" {
			return false, nil
		}
		certUrl = orderResponse.Certificate

		return true, nil
	})

	if err != nil {
		return "", err
	}

	return certUrl, nil
}

// Finalize posts a CSR to the order finalize url. On success this causes the server
// to move the order to processing and issue the certificate.
func (c *client) Finalize() error {
	// create CSR
	certReq := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"},
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, certReq, c.privKey.Key)
	if err != nil {
		return err
	}

	// encode the CSR
	csrString := base64.RawURLEncoding.EncodeToString(csr)
	reqBody := struct {
		CSR string `json:"csr"`
	}{
		CSR: csrString,
	}

	reqBodyStr, err := json.Marshal(&reqBody)
	if err != nil {
		return err
	}

	// post to finalize
	respBody, _, err := c.postAPIWithNonceRetry(c.orderResponse.Finalize, reqBodyStr, false)
	if err != nil {
		return err
	}

	// returns an order as "processing"
	order := &OrderResponse{}
	err = json.Unmarshal(respBody, order)
	if err != nil {
		return err
	}

	if order.Status != "processing" && order.Status != "valid" {
		return fmt.Errorf("finalize did not return an order in processing or valid state: %s", order.Status)
	}

	return nil
}

// SendTryChallenge tells the server to try the auth challenge
func (c *client) SendTryChallenge() error {
	chal, err := c.getHttpChallenge()
	if err != nil {
		return err
	}

	// send "{}": https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-8.3
	_, _, err = c.postAPIWithNonceRetry(chal.ChallengeUrl, []byte("{}"), false)
	if err != nil {
		return err
	}

	return nil
}

// SetupChallenge sets up an http-01 challenge at challengeAddr
func (c *client) SetupChallenge(challengeAddr string) (*http.Server, error) {
	chal, err := c.getHttpChallenge()
	if err != nil {
		return nil, err
	}

	srv := &http.Server{Addr: challengeAddr}

	keyAuthUrl := "/.well-known/acme-challenge/" + chal.ChallengeToken
	fmt.Printf("setting up challenge at %q\n", keyAuthUrl)

	// set up http challenge
	http.HandleFunc(keyAuthUrl, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)

		challengeString := chal.ChallengeToken + "." + c.accountKeyThumbprint()
		fmt.Printf("responded to challenge with %q\n", challengeString)
		fmt.Fprint(w, challengeString)
	})

	go func() {
		httpErr := srv.ListenAndServe()
		if httpErr != nil {
			err = httpErr
		}
	}()

	if err != nil {
		return nil, err
	}

	return srv, nil
}

func (c *client) signEmbedded(data []byte, url string) (*jose.JSONWebSignature, error) {
	signer, err := jose.NewSigner(c.privKey, &jose.SignerOptions{
		NonceSource: c,
		EmbedJWK:    true,
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": url,
		},
	})
	if err != nil {
		return nil, err
	}

	signed, err := signer.Sign(data)
	if err != nil {
		return nil, err
	}
	return signed, nil
}

func (c *client) signKeyID(data []byte, url string) (*jose.JSONWebSignature, error) {
	jwk := &jose.JSONWebKey{
		Key:       c.privKey.Key,
		Algorithm: "RSA",
		KeyID:     c.acctID,
	}

	signerKey := jose.SigningKey{
		Key:       jwk,
		Algorithm: jose.RS256,
	}

	opts := &jose.SignerOptions{
		NonceSource: c,
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": url,
		},
	}

	signer, err := jose.NewSigner(signerKey, opts)
	if err != nil {
		fmt.Printf("Err making signer: %#v\n", err)
		return nil, err
	}
	fmt.Printf("signKeyID data to sign: %v\n", string(data))
	signed, err := signer.Sign(data)
	if err != nil {
		fmt.Printf("Err using signer: %#v\n", err)
		return nil, err
	}
	return signed, nil
}

func (c *client) updateDirectory() error {
	fmt.Printf("Requesting directory from %q\n", c.server.String())
	respBody, _, err := c.getAPI(c.server.String())
	if err != nil {
		return err
	}

	var directory map[string]interface{}
	err = json.Unmarshal(respBody, &directory)
	if err != nil {
		return err
	}

	c.directory = directory
	return nil
}

func (c *client) updateNonce() error {
	if rawNonceURL, present := c.directory["newNonce"]; !present || rawNonceURL.(string) == "" {
		return fmt.Errorf("Missing \"newNonce\" entry in server directory")
	}
	nonceURL := c.directory["newNonce"].(string)
	fmt.Printf("Requesting nonce from %q\n", nonceURL)

	before := c.nonce
	_, _, err := c.getAPI(nonceURL)
	if err != nil {
		return err
	}
	after := c.nonce

	if before == after {
		return fmt.Errorf("Did not receive a fresh nonce from newNonce URL")
	}
	return nil
}

func (c *client) register() error {
	if acctURL, ok := c.directory["newAccount"]; !ok || acctURL.(string) == "" {
		return fmt.Errorf("Missing \"newAccount\" entry in server directory")
	}
	acctURL := c.directory["newAccount"].(string)
	fmt.Printf("Registering new account with %q\n", acctURL)

	reqBody := struct {
		ToSAgreed bool `json:"termsOfServiceAgreed"`
		Contact   []string
	}{
		ToSAgreed: true,
		Contact:   []string{"mailto:" + c.email},
	}

	reqBodyStr, err := json.Marshal(&reqBody)
	if err != nil {
		return err
	}

	// Registration is a unique case where we _do_ want the JWK to be embedded (vs
	// using a Key ID) so we invoke `postAPI` with `true` for the embed argument.
	_, resp, err := c.postAPIWithNonceRetry(acctURL, reqBodyStr, true)
	if err != nil {
		return err
	}

	locHeader := resp.Header.Get("Location")
	if locHeader == "" {
		return fmt.Errorf("No 'location' header with account URL in response")
	}

	c.acctID = locHeader
	return nil
}

type BadNonce struct {
	Type   string
	Detail string
	Status int
}

func (c *client) postAPIWithNonceRetry(url string, body []byte, embedJWK bool) ([]byte, *http.Response, error) {
	for {
		respBody, resp, err := c.postAPI(url, body, embedJWK)
		if err != nil {
			if resp.StatusCode != http.StatusBadRequest {
				fmt.Printf("nonce retry: got a non 400 error %v\n", resp.StatusCode)
				return nil, nil, err
			}
			realErr := err
			badNonceDetails := &BadNonce{}
			err = json.Unmarshal(respBody, badNonceDetails)
			if err != nil {
				fmt.Printf("nonce retry: error decoding bad nonce message %s\n", err)
				return nil, nil, err
			}
			if badNonceDetails.Type == "urn:ietf:params:acme:error:badNonce" {
				fmt.Printf("nonce retry: got badNonce type, updating nonce and retrying\n")
				c.updateNonce()
				continue
			}
			fmt.Printf("nonce retry: error but not for badNonce\n")
			return nil, nil, realErr
		}
		return respBody, resp, nil
	}
}

func (c *client) accountKeyThumbprint() string {
	key := c.privKey.Key.(*rsa.PrivateKey)
	print, _ := acme.JWKThumbprint(key.Public())
	return print
}

func (c *client) getHttpChallenge() (*ChallengeInfo, error) {
	if c.challengeResponse == nil {
		return nil, fmt.Errorf("challengeResponse is nil")
	}

	for _, chal := range c.challengeResponse.Challenges {
		if chal.ChallengeType == "http-01" {
			return &ChallengeInfo{
				ChallengeType:   chal.ChallengeType,
				ChallengeUrl:    chal.ChallengeUrl,
				ChallengeToken:  chal.ChallengeToken,
				ChallengeStatus: chal.ChallengeStatus,
			}, nil
		}
	}
	return nil, fmt.Errorf("no http challenge")
}

// Nonce satisfies the JWS "NonceSource" interface
func (c *client) Nonce() (string, error) {
	n := c.nonce
	err := c.updateNonce()
	if err != nil {
		return n, err
	}
	return n, nil
}

func (c *client) doReq(req *http.Request) ([]byte, *http.Response, error) {
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if n := resp.Header.Get("Replay-Nonce"); n != "" {
		c.nonce = n
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}

	// may be an invalid nonce
	if resp.StatusCode == http.StatusBadRequest {
		return respBody, resp, fmt.Errorf("badRequest")
	}

	if resp.StatusCode/100 != 2 {
		return respBody, resp, fmt.Errorf("Response %d: %s", resp.StatusCode, respBody)
	}
	return respBody, resp, nil
}

func (c *client) getAPI(url string) ([]byte, *http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", userAgent())
	req.Header.Set("Accept-Language", locale)
	return c.doReq(req)
}

func (c *client) postAPI(url string, body []byte, embedJWK bool) ([]byte, *http.Response, error) {
	var signedBody *jose.JSONWebSignature
	var err error

	if embedJWK {
		signedBody, err = c.signEmbedded(body, url)
	} else {
		signedBody, err = c.signKeyID(body, url)
	}

	if err != nil {
		return nil, nil, err
	}

	bodyBuf := bytes.NewBuffer([]byte(signedBody.FullSerialize()))
	req, err := http.NewRequest("POST", url, bodyBuf)
	if err != nil {
		return nil, nil, err
	}

	req.Header.Set("Content-Type", "application/jose+json")
	req.Header.Set("User-Agent", userAgent())
	req.Header.Set("Accept-Language", locale)
	return c.doReq(req)
}

func (c *client) readJSON() ([]byte, error) {
	var jsonBuf string

	scanner := bufio.NewScanner(os.Stdin)
	fmt.Printf("$> Enter JSON body, empty line to finish : \n")
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || line == "exit" || line == "q" {
			break
		}
		jsonBuf += line
	}

	var indented bytes.Buffer
	err := json.Indent(&indented, []byte(jsonBuf), "", "  ")
	return indented.Bytes(), err
}
