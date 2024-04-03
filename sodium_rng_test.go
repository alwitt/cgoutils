package cgoutils_test

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/alwitt/cgoutils"
	"github.com/apex/log"
	"github.com/stretchr/testify/assert"
)

func TestSodiumRandomBuf(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	sodium, err := cgoutils.NewSodiumCrypto(log.Fields{})
	assert.Nil(err)

	uut, err := sodium.GetRandomBuf(context.Background(), 64)
	assert.Nil(err)
	assert.NotNil(uut)
	buf, err := uut.GetSlice()
	assert.Nil(err)
	assert.Len(buf, 64)

	log.Debug(base64.StdEncoding.EncodeToString(buf))
}
