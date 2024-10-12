package crypto

import (
	"context"
	"fmt"
)

// AEADTypeEnum AEAD type description ENUM
type AEADTypeEnum string

// Supported AEAD types
const (
	AEADTypeXChaCha20Poly1305 AEADTypeEnum = "XChaCha20-Poly1305"
	AEADTypeAes256gcm         AEADTypeEnum = "AES256-GCM"
)

/*
GetAEAD define a new AEAD instance

	@param ctxt context.Context - calling context
	@param aeadType AEADTypeEnum - the AEAD implementation to use
	@returns the AEAD generator
*/
func (c *engineImpl) GetAEAD(_ context.Context, aeadType AEADTypeEnum) (AEAD, error) {
	switch aeadType {
	case AEADTypeXChaCha20Poly1305:
		return &sodiumXChaCha20Poly1305AEAD{core: c}, nil
	default:
		return nil, fmt.Errorf("does not support AEAD type %s", aeadType)
	}
}
