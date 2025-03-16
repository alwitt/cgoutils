package crypto

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"reflect"
	"time"

	"github.com/apex/log"
)

// CertParams set of parameters needed when defining a certificate
type CertParams struct {
	// SerialNumber cert serial number
	SerialNumber *big.Int
	// Subject certificate subject
	Subject pkix.Name
	// DNSNames DNS subject alt name
	DNSNames []string
	// EmailAddresses Email subject alt name
	EmailAddresses []string
	// IPAddresses IP subject alt name
	IPAddresses []net.IP
	// URIs URI subject all name
	URIs []*url.URL
	// NotBefore this cert is valid after this time
	NotBefore time.Time
	// NotAfter this cert is invalid after this time
	NotAfter time.Time
	// KeyUsage primary purpose of the certificate
	KeyUsage x509.KeyUsage
	// ExtKeyUsage additional usage of the certificate
	ExtKeyUsage []x509.ExtKeyUsage
}

/*
CreateED25519SelfSignedCA create an ED25519 self-signed certificate authority

	@param ctxt context.Context - calling context
	@param caParams CertParams - CA cert generation parameters
	@returns the ed25519 private key and the associated certificate
*/
func (c *engineImpl) CreateED25519SelfSignedCA(
	ctxt context.Context, caParams CertParams,
) (ed25519.PrivateKey, []byte, error) {
	logTags := c.GetLogTagsForContext(ctxt)

	// Generate a new ed25519 key pair
	pubKey, privKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.WithError(err).WithFields(logTags).Error("Failed to generate ED25519 key pair")
		return nil, nil, err
	}

	// Define certificate parameters
	certSpec := &x509.Certificate{
		SerialNumber:   caParams.SerialNumber,
		Subject:        caParams.Subject,
		DNSNames:       caParams.DNSNames,
		EmailAddresses: caParams.EmailAddresses,
		IPAddresses:    caParams.IPAddresses,
		URIs:           caParams.URIs,
		NotBefore:      caParams.NotBefore,
		NotAfter:       caParams.NotAfter,
		IsCA:           true,
		ExtKeyUsage:    caParams.ExtKeyUsage,
		KeyUsage:       caParams.KeyUsage,
	}

	// Generate the cert
	cert, err := x509.CreateCertificate(rand.Reader, certSpec, certSpec, pubKey, privKey)
	if err != nil {
		log.WithError(err).WithFields(logTags).Error("Failed to generate ED25519 self-signed CA cert")
		return nil, nil, err
	}

	// Convert the certificate to PEM format
	return privKey, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}), nil
}

// CertSigningRequestParams set of parameters needed when defining a CSR
type CertSigningRequestParams struct {
	// Subject certificate subject
	Subject pkix.Name
	// DNSNames DNS subject alt name
	DNSNames []string
	// EmailAddresses Email subject alt name
	EmailAddresses []string
	// IPAddresses IP subject alt name
	IPAddresses []net.IP
	// URIs URI subject all name
	URIs []*url.URL
}

/*
CreateED25519CSR create an ED25519 private key and associated certificate signing request

	@param ctxt context.Context - calling context
	@param csrParams CertSigningRequestParams - CSR generation parameters
	@returns the ed25519 private key and the associated certificate signing request
*/
func (c *engineImpl) CreateED25519CSR(
	ctxt context.Context, csrParams CertSigningRequestParams,
) (ed25519.PrivateKey, []byte, error) {
	logTags := c.GetLogTagsForContext(ctxt)

	// Generate a new ed25519 key pair
	_, privKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.WithError(err).WithFields(logTags).Error("Failed to generate ED25519 key pair")
		return nil, nil, err
	}

	csrReqParams := &x509.CertificateRequest{
		SignatureAlgorithm: x509.PureEd25519,
		Subject:            csrParams.Subject,
		DNSNames:           csrParams.DNSNames,
		EmailAddresses:     csrParams.EmailAddresses,
		IPAddresses:        csrParams.IPAddresses,
		URIs:               csrParams.URIs,
	}

	// Generate the CSR
	csrPayload, err := x509.CreateCertificateRequest(rand.Reader, csrReqParams, privKey)
	if err != nil {
		log.WithError(err).WithFields(logTags).Error("Failed to generate ED25519 CSR")
		return nil, nil, err
	}

	// Convert the CSR to PEM format
	return privKey, pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrPayload},
	), nil
}

/*
ParseCertificateFromPEM parse a PEM block for a certificate

	@param ctxt context.Context - calling context
	@param certPem string - the PEM string
	@returns the parsed certificate
*/
func (c *engineImpl) ParseCertificateFromPEM(
	ctxt context.Context, certPem string,
) (*x509.Certificate, error) {
	logTags := c.GetLogTagsForContext(ctxt)

	// PEM decode the certificate
	pemBlock, _ := pem.Decode([]byte(certPem))
	if pemBlock == nil {
		err := fmt.Errorf("failed to parse out a PEM block from input")
		log.WithError(err).WithFields(logTags).Error("Failed to PEM decode a certificate")
		return nil, err
	}
	if pemBlock.Bytes == nil {
		err := fmt.Errorf("read empty payload from the PEM block")
		log.WithError(err).WithFields(logTags).Error("Certificate contained no payload")
		return nil, err
	}

	// Parse the DER encoded string for a certificate
	return x509.ParseCertificate(pemBlock.Bytes)
}

/*
ReadED25519PublicKeyFromCert read the ED25519 public from certificate

	@param ctxt context.Context - calling context
	@param cert *x509.Certificate - certificate
	@returns the ED25519 public key
*/
func (c *engineImpl) ReadED25519PublicKeyFromCert(
	_ context.Context, cert *x509.Certificate,
) (ed25519.PublicKey, error) {
	if x509.Ed25519 != cert.PublicKeyAlgorithm {
		err := fmt.Errorf("cert did not contain a ED25519 public key")
		return nil, err
	}
	asED25519, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		err := fmt.Errorf("cert object public key field was type '%s'", reflect.TypeOf(cert.PublicKey))
		return nil, err
	}
	return asED25519, nil
}
