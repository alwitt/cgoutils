package crypto

// #include <stdlib.h>
// #include <sodium.h>
import "C"

import (
	"context"
	"fmt"
	"unsafe"

	"github.com/alwitt/cgoutils/common"
	"github.com/alwitt/goutils"
	"github.com/apex/log"
)

// sodiumHasher libsodium hashing API warper
type sodiumHasher struct {
	state SecureCSlice
	key   SecureCSlice
	hash  []byte
}

/*
GetHasherKey get a key for the cryptographic hasher

	@param ctxt context.Context - calling context
*/
func (c *engineImpl) GetHasherKey(ctxt context.Context) (SecureCSlice, error) {
	key, err := c.GetRandomBuf(ctxt, C.crypto_generichash_KEYBYTES)
	if err != nil {
		return nil, goutils.NewRuntimeError("failed to define new hash key", err, true)
	}
	return key, nil
}

/*
GetHasher get a libsodium cryptographic hasher

	@param ctxt context.Context - calling context
	@param key CryptoCSlice - for keyed hashing function
	@returns the hasher
*/
func (c *engineImpl) GetHasher(ctxt context.Context, key SecureCSlice) (Hasher, error) {
	logTags := c.GetLogTagsForContext(ctxt)

	state, err := c.AllocateSecureCSlice(C.sizeof_crypto_generichash_state)
	if err != nil {
		log.WithError(err).WithFields(logTags).Error("Failed to initialize buffer for hasher state")
		return nil, goutils.NewRuntimeError(
			"failed to initialize buffer for hasher state", err, true,
		)
	}

	hasher := &sodiumHasher{
		state: state, key: key, hash: make([]byte, C.crypto_generichash_BYTES_MAX),
	}

	// Initialize the hasher
	if err := hasher.init(); err != nil {
		log.WithError(err).WithFields(logTags).Error("libsodium hasher failed to initialize")
		return nil, goutils.NewRuntimeError("libsodium hasher failed to initialize", err, true)
	}

	return hasher, nil
}

// init perform hasher initialization. This prepares the internal compute state
func (h *sodiumHasher) init() error {
	state, err := h.state.GetCArray()
	if err != nil {
		return goutils.NewRuntimeError("unable to get pointer to hasher state array", err, true)
	}
	var key unsafe.Pointer
	keySize := 0
	if h.key != nil {
		key, err = h.key.GetCArray()
		if err != nil {
			return goutils.NewRuntimeError("unable to get pointer to hasher key array", err, true)
		}
		keySize = C.crypto_generichash_KEYBYTES
	} else {
		key = nil
	}

	resp := int(C.crypto_generichash_init(
		(*C.crypto_generichash_state)(state),
		(*C.uchar)(key),
		C.size_t(keySize),
		C.crypto_generichash_BYTES_MAX,
	))
	if resp != 0 {
		return common.NewSodiumError(
			fmt.Sprintf("hasher failed on `crypto_generichash_init` call with %d", resp), nil, true,
		)
	}

	return nil
}

/*
Update update the hash compute with new data

	@param buf []byte - new data
*/
func (h *sodiumHasher) Update(buf []byte) error {
	state, err := h.state.GetCArray()
	if err != nil {
		return goutils.NewRuntimeError("unable to get pointer to hasher state array", err, true)
	}
	resp := int(C.crypto_generichash_update(
		(*C.crypto_generichash_state)(state),
		(*C.uchar)(unsafe.Pointer(&(buf[0]))),
		C.ulonglong(len(buf)),
	))
	if resp != 0 {
		return common.NewSodiumError(
			fmt.Sprintf("hasher failed on `crypto_generichash_update` call with %d", resp), nil, true,
		)
	}
	return nil
}

/*
Finalize finalize the hash computation
*/
func (h *sodiumHasher) Finalize() error {
	state, err := h.state.GetCArray()
	if err != nil {
		return goutils.NewRuntimeError("unable to get pointer to hasher state array", err, true)
	}
	resp := int(C.crypto_generichash_final(
		(*C.crypto_generichash_state)(state),
		(*C.uchar)(unsafe.Pointer(&(h.hash[0]))),
		C.ulong(len(h.hash)),
	))
	if resp != 0 {
		return common.NewSodiumError(
			fmt.Sprintf("hasher failed on `crypto_generichash_final` call with %d", resp), nil, true,
		)
	}
	// Clear the state
	if err := h.state.Zero(); err != nil {
		return goutils.NewRuntimeError("unable to reset hasher state array", err, true)
	}
	return nil
}

/*
GetHash query the computed hash
*/
func (h *sodiumHasher) GetHash() []byte {
	return h.hash
}
