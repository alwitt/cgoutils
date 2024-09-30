package crypto

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"net/url"

	"github.com/apex/log"
)

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
CreateEd25519CSR create an ED25519 private key and associated certificate signing request

	@param ctxt context.Context - calling context
	@param csrParams CertSigningRequestParams - CSR generation parameters
	@returns the ed25519 private key and the associated certificate signing request
*/
func (c *engineImpl) CreateEd25519CSR(
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
