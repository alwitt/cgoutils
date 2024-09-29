package crypto_test

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/alwitt/cgoutils/crypto"
	"github.com/apex/log"
	"github.com/stretchr/testify/assert"
)

func TestSodiumRandomBuf(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	sodium, err := crypto.NewCryptoEngine(log.Fields{})
	assert.Nil(err)

	uut, err := sodium.GetRandomBuf(context.Background(), 64)
	assert.Nil(err)
	assert.NotNil(uut)
	buf, err := uut.GetSlice()
	assert.Nil(err)
	assert.Len(buf, 64)

	log.Debug(base64.StdEncoding.EncodeToString(buf))
}
