package crypto_test

import (
	"testing"

	"github.com/alwitt/cgoutils/crypto"
	"github.com/apex/log"
	"github.com/stretchr/testify/assert"
)

func TestSodiumCryptoInit(t *testing.T) {
	assert := assert.New(t)
	_, err := crypto.NewCryptoEngine(log.Fields{})
	assert.Nil(err)
	_, err = crypto.NewCryptoEngine(log.Fields{})
	assert.Nil(err)
}
