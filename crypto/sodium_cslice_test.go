package crypto_test

import (
	"encoding/json"
	"math/big"
	"runtime"
	"testing"
	"unsafe"

	"github.com/alwitt/cgoutils/crypto"
	"github.com/apex/log"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestSodiumCSlice(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	sodium, err := crypto.NewEngine(log.Fields{})
	assert.Nil(err)

	// Case 0: basic
	{
		uut, err := sodium.AllocateSecureCSlice(32)
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

		uut, err := sodium.AllocateSecureCSlice(64)
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

	// Case 2: increment value by one
	{
		uut, err := sodium.AllocateSecureCSlice(4)
		assert.Nil(err)
		buf, err := uut.GetSlice()
		assert.Nil(err)
		assert.Len(buf, 4)
		buf[0] = 0xff
		buf[1] = 0xff
		buf[2] = 0xff
		buf[3] = 0x7f
		buf, err = uut.GetSlice()
		assert.Nil(err)
		assert.EqualValues([]byte{0xff, 0xff, 0xff, 0x7f}, buf)
		assert.Nil(uut.IncrementValue())
		buf, err = uut.GetSlice()
		assert.Nil(err)
		assert.EqualValues([]byte{0, 0, 0, 0x80}, buf)
	}

	// Case 3: add value to slice
	{
		uut, err := sodium.AllocateSecureCSlice(4)
		assert.Nil(err)
		buf, err := uut.GetSlice()
		assert.Nil(err)
		assert.Len(buf, 4)
		buf[0] = 0x00
		buf[1] = 0x00
		buf[2] = 0x00
		buf[3] = 0x00
		buf, err = uut.GetSlice()
		assert.Nil(err)
		assert.EqualValues([]byte{0, 0, 0, 0}, buf)
		assert.NotPanics(func() {
			assert.Nil(uut.AddValue(big.NewInt(4310)))
		})
		buf, err = uut.GetSlice()
		assert.Nil(err)
		assert.EqualValues([]byte{0xd6, 0x10, 0, 0}, buf)
	}

	// Case 4: allocated in a loop
	{
		log.SetLevel(log.InfoLevel)
		for idx := 0; idx < 1000; idx++ {
			uut, err := sodium.AllocateSecureCSlice(8192)
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
