package crypto

// #include <stdlib.h>
// #include <sodium.h>
import "C"

import (
	"context"

	"github.com/apex/log"
)

/*
GetRandomBuf get a buffer of random data with the specified length

	@param ctxt context.Context - calling context
	@param length int - the length of the buffer to fill
*/
func (c *sodiumCrypto) GetRandomBuf(ctxt context.Context, length int) (SecureCSlice, error) {
	logTags := c.GetLogTagsForContext(ctxt)
	logTags["length"] = length

	// Prepare new buffer
	newBuf, err := c.AllocateSecureCSlice(length)
	if err != nil {
		log.WithError(err).WithFields(logTags).Error("Failed to prepare buffer")
		return nil, err
	}

	// Get the random data
	bufPtr, err := newBuf.GetCArray()
	if err != nil {
		log.WithError(err).WithFields(logTags).Error("Unable to access raw C pointer of buffer")
		return nil, err
	}

	log.WithFields(logTags).Debug("Getting random bytes...")
	C.randombytes_buf(bufPtr, C.size_t(length))
	log.WithFields(logTags).Debug("Got random bytes.")

	return newBuf, nil
}
