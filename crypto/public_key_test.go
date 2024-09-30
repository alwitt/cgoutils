package crypto_test

import (
	"context"
	"crypto/x509/pkix"
	"testing"

	"github.com/alwitt/cgoutils/crypto"
	"github.com/apex/log"
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

		priv, csr, err := engine.CreateEd25519CSR(utCtxt, params)
		assert.Nil(err)
		assert.NotNil(priv)
		log.Debugf("CSR\n%s", string(csr))
	}
}
