package cgoutils

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

// sodiumCrypto `libsodium` wrapper client which implements Crypto
type sodiumCrypto struct {
	goutils.Component
}

/*
NewSodiumCrypto define a `libsodium` backed Crypto object.

	@returns new Crypto object
*/
func NewSodiumCrypto(logTags log.Fields) (Crypto, error) {
	instance := &sodiumCrypto{
		Component: goutils.Component{LogTags: logTags},
	}
	return instance, instance.init()
}

// init initialize `libsodium` for use
func (c *sodiumCrypto) init() error {
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
AllocateCryptoCSlice allocate a libsodium secure memory backed slice

	@param length uint64 - length of the array
	@return CSlice object
*/
func (c *sodiumCrypto) AllocateCryptoCSlice(length int) (CryptoCSlice, error) {
	instance := &sodiumCSlice{core: nil}
	return instance, instance.allocate(length)
}
