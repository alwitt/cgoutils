package cgoutils_test

import (
	"encoding/json"
	"testing"

	"github.com/alwitt/cgoutils"
	"github.com/apex/log"
	"github.com/stretchr/testify/assert"
)

func TestBasicCSlice(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	// Case 0: basic
	{
		uut, err := cgoutils.AllocateBasicCSlice(32)
		assert.Nil(err)

		bufLen, err := uut.GetLen()
		assert.Nil(err)
		assert.Equal(32, bufLen)
		buf, err := uut.GetSlice()
		assert.Nil(err)
		assert.NotNil(buf)
		assert.Len(buf, 32)
	}

	// Case 1: allocated in a loop
	{
		for idx := 0; idx < 1000; idx++ {
			uut, err := cgoutils.AllocateBasicCSlice(8192)
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

	// Case 2: transfer data via buffer
	{
		type testStructure struct {
			A string
			B int
			C bool
		}

		test, err := json.Marshal(&testStructure{A: "hello", B: -42, C: true})
		assert.Nil(err)

		uut, err := cgoutils.AllocateBasicCSlice(64)
		assert.Nil(err)

		// Copy the data over
		{
			buf, err := uut.GetSlice()
			assert.Nil(err)
			copy(buf, test)
		}

		// Unmarshal using the new buffer
		{
			buf, err := uut.GetSlice()
			assert.Nil(err)
			log.Debugf("Stored '%s'", string(buf))
			assert.EqualValues(test, buf[:len(test)])
		}
	}
}
