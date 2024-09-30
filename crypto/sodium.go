package crypto

// #cgo CFLAGS: -Wall
// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"

import (
	"context"
	"fmt"

	"github.com/apex/log"
)

// init initialize `libsodium` for use
func (c *engineImpl) init() error {
	logTags := c.GetLogTagsForContext(context.Background())

	resp := int(C.sodium_init())

	if resp == -1 {
		return fmt.Errorf("failed to initialize 'libsodium'")
	}
	if resp == 1 {
		log.WithFields(logTags).Debug("libsodium already initialized")
	}
	return nil
}

/*
AllocateSecureCSlice allocate a libsodium secure memory backed slice

	@param length uint64 - length of the array
	@return CSlice object
*/
func (c *engineImpl) AllocateSecureCSlice(length int) (SecureCSlice, error) {
	instance := &sodiumCSlice{core: nil}
	return instance, instance.allocate(length)
}
