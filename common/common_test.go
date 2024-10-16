package common_test

import (
	"encoding/json"
	"runtime"
	"testing"
	"unsafe"

	"github.com/alwitt/cgoutils/common"
	"github.com/apex/log"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestBasicCSlice(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	// Case 0: basic
	{
		uut, err := common.AllocateBasicCSlice(32)
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

		uut, err := common.AllocateBasicCSlice(64)
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
		log.SetLevel(log.InfoLevel)
		for idx := 0; idx < 1000; idx++ {
			uut, err := common.AllocateBasicCSlice(8192)
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
