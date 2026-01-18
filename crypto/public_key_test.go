package crypto_test

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/alwitt/cgoutils/crypto"
	"github.com/apex/log"
	"github.com/go-resty/resty/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestCreateEd25519SelfSignedCA(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtxt := context.Background()

	engine, err := crypto.NewEngine(log.Fields{})
	assert.Nil(err)

	current := time.Now().UTC()

	// Case 0: basic usage
	{
		params := crypto.CertParams{
			SerialNumber: big.NewInt(42),
			Subject:      pkix.Name{CommonName: "unit-tester@testing.com"},
			DNSNames:     []string{"unit-test.testing.com", "testing.com"},
			NotBefore:    current,
			NotAfter:     current.AddDate(0, 6, 0),
			KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		}

		priv, cert, err := engine.CreateED25519SelfSignedCA(utCtxt, params)
		assert.Nil(err)
		assert.NotNil(priv)
		assert.NotEmpty(cert)

		// Parse the cert again
		caCert, err := engine.ParseCertificateFromPEM(utCtxt, string(cert))
		assert.Nil(err)
		assert.NotNil(caCert)

		// Verify certificate parameters
		assert.Equal(0, caCert.SerialNumber.Cmp(big.NewInt(42)))
		assert.Equal(params.Subject.CommonName, caCert.Subject.CommonName)
		assert.EqualValues(params.DNSNames, caCert.DNSNames)
		assert.Equal(params.KeyUsage, caCert.KeyUsage)
		// Verify public key
		pub, err := engine.ReadED25519PublicKeyFromCert(utCtxt, caCert)
		assert.Nil(err)
		assert.EqualValues(priv.Public(), pub)
	}
}

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

	if runningInCICD() {
		log.Debug("Skip live CFSSL testing in CICD")
		return
	}

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

func TestRSALoadFromPEM(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtxt := context.Background()

	engine, err := crypto.NewEngine(log.Fields{"component": "crypto-engine"})
	assert.Nil(err)

	testCertFile, err := os.Open("../test/ut_rsa.crt")
	assert.Nil(err)
	defer func() {
		assert.Nil(testCertFile.Close())
	}()
	testKeyFile, err := os.Open("../test/ut_rsa.key")
	assert.Nil(err)
	defer func() {
		assert.Nil(testKeyFile.Close())
	}()

	testCert, err := io.ReadAll(testCertFile)
	assert.Nil(err)
	testKey, err := io.ReadAll(testKeyFile)
	assert.Nil(err)

	parsedCert, err := engine.ParseCertificateFromPEM(utCtxt, string(testCert))
	assert.Nil(err)
	parsedKey, err := engine.ParseRSAPrivateKeyFromPEM(utCtxt, string(testKey))
	assert.Nil(err)

	parsedPub, err := engine.ReadRSAPublicKeyFromCert(utCtxt, parsedCert)
	assert.Nil(err)

	assert.True(parsedKey.PublicKey.Equal(parsedPub))
}

func TestRSAEncryption(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtxt := context.Background()

	engine, err := crypto.NewEngine(log.Fields{"component": "crypto-engine"})
	assert.Nil(err)

	testCertFile, err := os.Open("../test/ut_rsa.crt")
	assert.Nil(err)
	defer func() {
		assert.Nil(testCertFile.Close())
	}()
	testKeyFile, err := os.Open("../test/ut_rsa.key")
	assert.Nil(err)
	defer func() {
		assert.Nil(testKeyFile.Close())
	}()

	testCert, err := io.ReadAll(testCertFile)
	assert.Nil(err)
	testKey, err := io.ReadAll(testKeyFile)
	assert.Nil(err)

	parsedCert, err := engine.ParseCertificateFromPEM(utCtxt, string(testCert))
	assert.Nil(err)
	parsedKey, err := engine.ParseRSAPrivateKeyFromPEM(utCtxt, string(testKey))
	assert.Nil(err)

	parsedPub, err := engine.ReadRSAPublicKeyFromCert(utCtxt, parsedCert)
	assert.Nil(err)

	plainText := []byte(uuid.NewString())

	cipherText, err := engine.RSAEncrypt(utCtxt, plainText, parsedPub, nil)
	assert.Nil(err)

	decrypted, err := engine.RSADecrypt(utCtxt, cipherText, parsedKey, nil)
	assert.Nil(err)

	assert.EqualValues(plainText, decrypted)
}

func TestRSAEncryptionWrongLabel(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtxt := context.Background()

	engine, err := crypto.NewEngine(log.Fields{"component": "crypto-engine"})
	assert.Nil(err)

	testCertFile, err := os.Open("../test/ut_rsa.crt")
	assert.Nil(err)
	defer func() {
		assert.Nil(testCertFile.Close())
	}()
	testKeyFile, err := os.Open("../test/ut_rsa.key")
	assert.Nil(err)
	defer func() {
		assert.Nil(testKeyFile.Close())
	}()

	testCert, err := io.ReadAll(testCertFile)
	assert.Nil(err)
	testKey, err := io.ReadAll(testKeyFile)
	assert.Nil(err)

	parsedCert, err := engine.ParseCertificateFromPEM(utCtxt, string(testCert))
	assert.Nil(err)
	parsedKey, err := engine.ParseRSAPrivateKeyFromPEM(utCtxt, string(testKey))
	assert.Nil(err)

	parsedPub, err := engine.ReadRSAPublicKeyFromCert(utCtxt, parsedCert)
	assert.Nil(err)

	plainText := []byte(uuid.NewString())

	label := []byte(uuid.NewString())

	cipherText, err := engine.RSAEncrypt(utCtxt, plainText, parsedPub, label)
	assert.Nil(err)

	_, err = engine.RSADecrypt(utCtxt, cipherText, parsedKey, []byte(uuid.NewString()))
	assert.NotNil(err)

	decrypted, err := engine.RSADecrypt(utCtxt, cipherText, parsedKey, label)
	assert.Nil(err)

	assert.EqualValues(plainText, decrypted)
}
