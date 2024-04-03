package cgoutils_test

import (
	"testing"

	"github.com/alwitt/cgoutils"
	"github.com/apex/log"
	"github.com/stretchr/testify/assert"
)

func TestSodiumCryptoInit(t *testing.T) {
	assert := assert.New(t)
	_, err := cgoutils.NewSodiumCrypto(log.Fields{})
	assert.Nil(err)
	_, err = cgoutils.NewSodiumCrypto(log.Fields{})
	assert.Nil(err)
}
