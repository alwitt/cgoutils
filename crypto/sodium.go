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

// engineImpl implements Engine interface
type engineImpl struct {
	goutils.Component
}

/*
NewEngine define a new Engine object.

	@param logTags log.Fields - component log tags
	@returns new Engine object
*/
func NewEngine(logTags log.Fields) (Engine, error) {
	instance := &engineImpl{
		Component: goutils.Component{
			LogTags: logTags,
			LogTagModifiers: []goutils.LogMetadataModifier{
				goutils.ModifyLogMetadataByRestRequestParam,
			},
		},
	}
	return instance, instance.init()
}

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
