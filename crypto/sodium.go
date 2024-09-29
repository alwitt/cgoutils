package crypto

// #cgo CFLAGS: -Wall
// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"

import (
	"context"
	"fmt"

	"github.com/alwitt/goutils"
	"github.com/apex/log"
)

// sodiumCryptoEngine `libsodium` wrapper client which implements Crypto
type sodiumCryptoEngine struct {
	goutils.Component
}

/*
NewCryptoEngine define a `libsodium` backed Crypto object.

	@returns new Crypto object
*/
func NewCryptoEngine(logTags log.Fields) (Engine, error) {
	instance := &sodiumCryptoEngine{
		Component: goutils.Component{LogTags: logTags},
	}
	return instance, instance.init()
}

// init initialize `libsodium` for use
func (c *sodiumCryptoEngine) init() error {
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
func (c *sodiumCryptoEngine) AllocateSecureCSlice(length int) (SecureCSlice, error) {
	instance := &sodiumCSlice{core: nil}
	return instance, instance.allocate(length)
}
