package crypto_test

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/alwitt/cgoutils/crypto"
	"github.com/apex/log"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestSodiumHashing(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtxt := context.Background()

	sodium, err := crypto.NewEngine(log.Fields{})
	assert.Nil(err)

	// Case 0: basic usage
	{
		key, err := sodium.GetHasherKey(utCtxt)
		assert.Nil(err)

		uut, err := sodium.GetHasher(utCtxt, key)
		assert.Nil(err)

		test := []string{uuid.NewString(), uuid.NewString(), uuid.NewString()}
		for _, buf := range test {
			assert.Nil(uut.Update([]byte(buf)))
		}
		assert.Nil(uut.Finalize())

		hash := uut.GetHash()
		log.Debug(base64.StdEncoding.EncodeToString(hash))
	}

	// Case 1: Hash uniqueness
	{
		key, err := sodium.GetHasherKey(utCtxt)
		assert.Nil(err)

		uut1, err := sodium.GetHasher(utCtxt, key)
		assert.Nil(err)
		uut2, err := sodium.GetHasher(utCtxt, key)
		assert.Nil(err)

		test := []string{uuid.NewString(), uuid.NewString(), uuid.NewString()}
		for _, buf := range test {
			assert.Nil(uut1.Update([]byte(buf)))
			assert.Nil(uut2.Update([]byte(buf)))
		}
		assert.Nil(uut1.Finalize())
		assert.Nil(uut2.Finalize())

		hash1 := uut1.GetHash()
		hash2 := uut2.GetHash()
		assert.EqualValues(hash1, hash2)
		log.Debug(base64.StdEncoding.EncodeToString(hash1))
		log.Debug(base64.StdEncoding.EncodeToString(hash2))
	}
}
