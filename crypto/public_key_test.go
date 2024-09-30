package crypto_test

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/alwitt/cgoutils/crypto"
	"github.com/apex/log"
	"github.com/go-resty/resty/v2"
	"github.com/stretchr/testify/assert"
)

func TestCreateEd25519CSR(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtxt := context.Background()

	engine, err := crypto.NewEngine(log.Fields{})
	assert.Nil(err)

	// Case 0: basic usage
	{
		params := crypto.CertSigningRequestParams{
			Subject:  pkix.Name{CommonName: "unit-tester@testing.com"},
			DNSNames: []string{"unit-test.testing.com", "testing.com"},
		}

		priv, csr, err := engine.CreateED25519CSR(utCtxt, params)
		assert.Nil(err)
		assert.NotNil(priv)
		log.Debugf("CSR\n%s", string(csr))
	}
}

func TestCertificateParsing(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtxt := context.Background()

	engine, err := crypto.NewEngine(log.Fields{})
	assert.Nil(err)

	cert := `-----BEGIN CERTIFICATE-----
MIIBsjCCAWSgAwIBAgIUcYNqAQvKpfw0FEZfTItFQXsg4KkwBQYDK2VwMCkxCzAJ
BgNVBAYTAlVTMRowGAYDVQQDExF0ZXN0aW5nLmxvY2FsLmRldjAeFw0yNDA5MzAw
MjUxMDBaFw0yNjA5MzAwMjUxMDBaMCcxCzAJBgNVBAYTAkRFMRgwFgYDVQQDEw93
d3cuZXhhbXBsZS5jb20wKjAFBgMrZXADIQDVHupY4jHgYWRAgYPpEBoQmUmuE8JP
+4v4oYG1E+1do6OBnzCBnDAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYB
BQUHAwEwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUHsRxtvCswvEBqtlhJ+FkKqtF
e4EwHwYDVR0jBBgwFoAUoYKj6hIKwZtXv646Gudf+slJy1swJwYDVR0RBCAwHoIP
d3d3LmV4YW1wbGUuY29tggtleGFtcGxlLmNvbTAFBgMrZXADQQAin3oxPLeI9KKl
pT7pVeb6eBynECBN6LrRa4y8zpjRFH72gJ0YbAGSgG7V5Z4PLasCOzX8y+8TUO+w
JAXphZYE
-----END CERTIFICATE-----`

	// Case 0: basic usage
	parsedCert, err := engine.ParseCertificateFromPEM(utCtxt, cert)
	assert.Nil(err)
	assert.NotNil(parsedCert)
	assert.Equal("testing.local.dev", parsedCert.Issuer.CommonName)
	assert.Equal([]string{"www.example.com", "example.com"}, parsedCert.DNSNames)
	assert.Equal(x509.PureEd25519, parsedCert.SignatureAlgorithm)
	assert.Equal(x509.Ed25519, parsedCert.PublicKeyAlgorithm)
	_, err = engine.ReadED25519PublicKeyFromCert(utCtxt, parsedCert)
	assert.Nil(err)
}

func TestCertSigningEndToEnd(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtxt := context.Background()

	engine, err := crypto.NewEngine(log.Fields{"component": "crypto-engine"})
	assert.Nil(err)

	cfsslURL, err := getTestCFSSLBaseURL()
	assert.Nil(err)

	cfssl, err := crypto.NewCFSSLClient(
		log.Fields{"component": "cfssl-client"}, cfsslURL, resty.New(), "request-id",
	)
	assert.Nil(err)

	testCommonName := "unit-tester@testing.com"
	testSubAltNameDNS := []string{"unit-test.testing.com", "testing.com"}

	// Build CSR
	var priv ed25519.PrivateKey
	var csr []byte
	{
		params := crypto.CertSigningRequestParams{
			Subject:  pkix.Name{CommonName: testCommonName},
			DNSNames: testSubAltNameDNS,
		}

		priv, csr, err = engine.CreateED25519CSR(utCtxt, params)
		assert.Nil(err)
		assert.NotNil(priv)
		log.Debugf("CSR\n%s", string(csr))
	}

	// Sign the CSR, and get certificate
	var parsedCert *x509.Certificate
	{
		lclCtxt, lclCancel := context.WithTimeout(utCtxt, time.Second*5)
		certStr, err := cfssl.SignCSR(lclCtxt, string(csr), "server")
		assert.Nil(err)
		lclCancel()
		log.Debugf("New Cert\n%s", certStr)

		// Parse the certificate
		parsedCert, err = engine.ParseCertificateFromPEM(utCtxt, certStr)
		assert.Nil(err)
		assert.NotNil(parsedCert)
	}

	// Verify the certificate
	assert.Equal("testing.local.dev", parsedCert.Issuer.CommonName)
	assert.Equal(testCommonName, parsedCert.Subject.CommonName)
	assert.Equal(testSubAltNameDNS, parsedCert.DNSNames)
	assert.Equal(x509.PureEd25519, parsedCert.SignatureAlgorithm)
	assert.Equal(x509.Ed25519, parsedCert.PublicKeyAlgorithm)
	signedPublicKey, err := engine.ReadED25519PublicKeyFromCert(utCtxt, parsedCert)
	assert.Nil(err)
	assert.Equal(priv.Public(), signedPublicKey)
}
