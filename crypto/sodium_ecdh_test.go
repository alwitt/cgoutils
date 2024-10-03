package crypto_test

import (
	"context"
	"testing"

	"github.com/alwitt/cgoutils/crypto"
	"github.com/apex/log"
	"github.com/stretchr/testify/assert"
)

func TestSodiumECDH(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtxt := context.Background()

	sodium, err := crypto.NewEngine(log.Fields{})
	assert.Nil(err)

	clientKeyPair, err := sodium.NewECDHKeyPair(utCtxt)
	assert.Nil(err)
	serverKeyPair, err := sodium.NewECDHKeyPair(utCtxt)
	assert.Nil(err)

	clientSessionKeys, err := sodium.ComputeClientECDHSessionKeys(
		utCtxt, clientKeyPair, serverKeyPair.Public,
	)
	assert.Nil(err)
	serverSessionKeys, err := sodium.ComputeServerECDHSessionKeys(
		utCtxt, serverKeyPair, clientKeyPair.Public,
	)
	assert.Nil(err)

	cRX, err := clientSessionKeys.RX.GetSlice()
	assert.Nil(err)
	cTX, err := clientSessionKeys.TX.GetSlice()
	assert.Nil(err)
	sRX, err := serverSessionKeys.RX.GetSlice()
	assert.Nil(err)
	sTX, err := serverSessionKeys.TX.GetSlice()
	assert.Nil(err)

	assert.EqualValues(cRX, sTX)
	assert.EqualValues(cTX, sRX)
}
