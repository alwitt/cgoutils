package cgoutils_test

import (
	"testing"

	"github.com/alwitt/cgoutils"
	"github.com/stretchr/testify/assert"
)

func TestSodiumCryptoInit(t *testing.T) {
	assert := assert.New(t)
	_, err := cgoutils.NewSodiumCrypto()
	assert.Nil(err)
}
