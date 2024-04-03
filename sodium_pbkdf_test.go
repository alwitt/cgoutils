package cgoutils_test

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/alwitt/cgoutils"
	"github.com/apex/log"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestSodiumPBKDF(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtxt := context.Background()

	sodium, err := cgoutils.NewSodiumCrypto(log.Fields{})
	assert.Nil(err)

	// Case 0: basic usage
	{
		password := "Hello World"

		salt, err := sodium.GetPBKDFSalt(utCtxt)
		assert.Nil(err)

		newKey, err := sodium.PBKDF(
			utCtxt,
			[]byte(password),
			salt,
			cgoutils.SodiumPBKDFOpsLimitFast,
			cgoutils.SodiumPBKDFMemLimitFast,
			32,
		)
		assert.Nil(err)

		key, err := newKey.GetSlice()
		assert.Nil(err)
		assert.Len(key, 32)
		log.Debug(base64.StdEncoding.EncodeToString(key))
	}

	// Case 1: repeatability
	{
		password := uuid.NewString()

		salt, err := sodium.GetPBKDFSalt(utCtxt)
		assert.Nil(err)

		newKey1, err := sodium.PBKDF(
			utCtxt,
			[]byte(password),
			salt,
			cgoutils.SodiumPBKDFOpsLimitFast,
			cgoutils.SodiumPBKDFMemLimitFast,
			32,
		)
		assert.Nil(err)

		newKey2, err := sodium.PBKDF(
			utCtxt,
			[]byte(password),
			salt,
			cgoutils.SodiumPBKDFOpsLimitFast,
			cgoutils.SodiumPBKDFMemLimitFast,
			32,
		)
		assert.Nil(err)

		key1, err := newKey1.GetSlice()
		assert.Nil(err)
		key2, err := newKey2.GetSlice()
		assert.Nil(err)
		assert.EqualValues(key1, key2)
	}

	// Case 2: variability
	{
		password := uuid.NewString()

		salt, err := sodium.GetPBKDFSalt(utCtxt)
		assert.Nil(err)

		newKey1, err := sodium.PBKDF(
			utCtxt,
			[]byte(password),
			salt,
			cgoutils.SodiumPBKDFOpsLimitFast,
			cgoutils.SodiumPBKDFMemLimitFast,
			32,
		)
		assert.Nil(err)

		newKey2, err := sodium.PBKDF(
			utCtxt,
			[]byte(password),
			salt,
			cgoutils.SodiumPBKDFOpsLimitMed,
			cgoutils.SodiumPBKDFMemLimitFast,
			32,
		)
		assert.Nil(err)

		key1, err := newKey1.GetSlice()
		assert.Nil(err)
		key2, err := newKey2.GetSlice()
		assert.Nil(err)
		assert.NotEqualValues(key1, key2)
	}
}
