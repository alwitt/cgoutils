package crypto

import (
	"context"
	"fmt"
	"math/big"

	"github.com/alwitt/goutils"
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
func (c *engineImpl) GetAEAD(ctxt context.Context, aeadType AEADTypeEnum) (AEAD, error) {
	switch aeadType {
	case AEADTypeXChaCha20Poly1305:
		return &sodiumXChaCha20Poly1305{core: c}, nil
	case AEADTypeAes256gcm:
		return c.newAES256GCM(ctxt)
	default:
		return nil, goutils.NewBadInputError(
			fmt.Sprintf("does not support AEAD type %s", aeadType), nil, true,
		)
	}
}

/*
getAEADNonceForIndex helper function that computes a AEAD nonce for Ith message within a stream

	@param msgIndex int64 - the message index within a stream
	@param c Engine - the crypto engine
	@param a AEAD - the AEAD requesting the nonce
	@returns nonce for Ith message
*/
func getAEADNonceForIndex(msgIndex int64, c Engine, a AEAD) (SecureCSlice, error) {
	// Make a copy of the nonce
	nonceCopy, err := c.AllocateSecureCSlice(a.ExpectedNonceLen())
	if err != nil {
		return nil, goutils.NewRuntimeError("unable to allocation nonce copy buffer", err, true)
	}
	{
		nonceCore, err := a.Nonce().GetSlice()
		if err != nil {
			return nil, goutils.NewRuntimeError("unable to get nonce buffer slice", err, true)
		}
		nonceCopyCore, err := nonceCopy.GetSlice()
		if err != nil {
			return nil, goutils.NewRuntimeError("unable to get nonce copy buffer slice", err, true)
		}
		copied := copy(nonceCopyCore, nonceCore)
		if copied != a.ExpectedNonceLen() {
			return nil, goutils.NewRuntimeError(
				fmt.Sprintf("unable to copy nonce value: %d =/= %d", copied, a.ExpectedNonceLen()),
				nil,
				true,
			)
		}
	}
	// Update the nonce copy by the message index within a stream
	if err := nonceCopy.AddValue(big.NewInt(msgIndex)); err != nil {
		return nil, goutils.NewRuntimeError(
			"unable to update nonce copy for stream message index", err, true,
		)
	}
	return nonceCopy, nil
}
