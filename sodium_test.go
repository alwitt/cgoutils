package cgoutils_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"runtime"
	"testing"
	"unsafe"

	"github.com/alwitt/cgoutils"
	"github.com/apex/log"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestSodiumCryptoInit(t *testing.T) {
	assert := assert.New(t)
	_, err := cgoutils.NewSodiumCrypto(log.Fields{})
	assert.Nil(err)
	_, err = cgoutils.NewSodiumCrypto(log.Fields{})
	assert.Nil(err)
}

func TestSodiumCSlice(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	sodium, err := cgoutils.NewSodiumCrypto(log.Fields{})
	assert.Nil(err)

	// Case 0: basic
	{
		uut, err := sodium.AllocateCryptoCSlice(32)
		assert.Nil(err)

		bufLen, err := uut.GetLen()
		assert.Nil(err)
		assert.Equal(32, bufLen)
		buf, err := uut.GetSlice()
		assert.Nil(err)
		assert.NotNil(buf)
		assert.Len(buf, 32)
	}

	// Case 1: transfer data via buffer
	{
		type testStructure struct {
			A string
			B int
			C bool
		}

		test, err := json.Marshal(&testStructure{A: uuid.New().String(), B: -42, C: true})
		assert.Nil(err)

		uut, err := sodium.AllocateCryptoCSlice(64)
		assert.Nil(err)

		// Copy the data over
		{
			buf, err := uut.GetSlice()
			assert.Nil(err)
			assert.Equal(len(test), copy(buf, test))
		}

		// Verify content
		{
			buf, err := uut.GetSlice()
			assert.Nil(err)
			log.Debugf("Stored '%s'", string(buf))
			assert.EqualValues(test, buf[:len(test)])
		}
		{
			buf, err := uut.GetCArray()
			assert.Nil(err)
			for idx, char := range test {
				assert.Equal(
					char, *(*byte)(unsafe.Pointer(uintptr(buf) + (uintptr(idx)))),
				)
			}
		}
	}

	// Case 2: allocated in a loop
	{
		for idx := 0; idx < 1000; idx++ {
			uut, err := sodium.AllocateCryptoCSlice(8192)
			assert.Nil(err)
			bufLen, err := uut.GetLen()
			assert.Nil(err)
			assert.Equal(8192, bufLen)
			buf, err := uut.GetSlice()
			assert.Nil(err)
			assert.NotNil(buf)
			assert.Len(buf, 8192)
		}
	}

	// Trigger GC
	runtime.GC()
}

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

func TestSodiumHashing(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtxt := context.Background()

	sodium, err := cgoutils.NewSodiumCrypto(log.Fields{})
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
