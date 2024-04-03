package cgoutils

// #include <stdlib.h>
// #include <sodium.h>
import "C"

import (
	"context"
	"fmt"
	"unsafe"

	"github.com/apex/log"
)

// sodiumHasher libsodium hashing API warper
type sodiumHasher struct {
	state CryptoCSlice
	key   CryptoCSlice
	hash  []byte
}

/*
GetHasherKey get a key for the cryptographic hasher

	@param ctxt context.Context - calling context
*/
func (c *sodiumCrypto) GetHasherKey(ctxt context.Context) (CryptoCSlice, error) {
	return c.GetRandomBuf(ctxt, C.crypto_generichash_KEYBYTES)
}

/*
GetHasher get a libsodium cryptographic hasher

	@param ctxt context.Context - calling context
	@param key CryptoCSlice - for keyed hashing function
	@returns the hasher
*/
func (c *sodiumCrypto) GetHasher(ctxt context.Context, key CryptoCSlice) (CryptoHasher, error) {
	logTags := c.GetLogTagsForContext(ctxt)

	state, err := c.AllocateCryptoCSlice(C.sizeof_crypto_generichash_state)
	if err != nil {
		log.WithError(err).WithFields(logTags).Error("Failed to initialize buffer for hasher state")
		return nil, err
	}

	hasher := &sodiumHasher{
		state: state, key: key, hash: make([]byte, C.crypto_generichash_BYTES_MAX),
	}

	// Initialize the hasher
	if err := hasher.init(); err != nil {
		log.WithError(err).WithFields(logTags).Error("libsodium hasher failed to initialize")
	}

	return hasher, nil
}

// init perform hasher initialization. This prepares the internal compute state
func (h *sodiumHasher) init() error {
	key, err := h.key.GetCArray()
	if err != nil {
		return err
	}
	state, err := h.state.GetCArray()
	if err != nil {
		return err
	}

	resp := int(C.crypto_generichash_init(
		(*C.crypto_generichash_state)(state),
		(*C.uchar)(key),
		C.crypto_generichash_KEYBYTES,
		C.crypto_generichash_BYTES_MAX,
	))
	if resp != 0 {
		return fmt.Errorf("hasher failed on `crypto_generichash_init` call with %d", resp)
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
		return err
	}
	resp := int(C.crypto_generichash_update(
		(*C.crypto_generichash_state)(state),
		(*C.uchar)(unsafe.Pointer(&(buf[0]))),
		C.ulonglong(len(buf)),
	))
	if resp != 0 {
		return fmt.Errorf("hasher failed on `crypto_generichash_update` call with %d", resp)
	}
	return nil
}

/*
Finalize finalize the hash computation
*/
func (h *sodiumHasher) Finalize() error {
	state, err := h.state.GetCArray()
	if err != nil {
		return err
	}
	resp := int(C.crypto_generichash_final(
		(*C.crypto_generichash_state)(state),
		(*C.uchar)(unsafe.Pointer(&(h.hash[0]))),
		C.ulong(len(h.hash)),
	))
	if resp != 0 {
		return fmt.Errorf("hasher failed on `crypto_generichash_final` call with %d", resp)
	}
	// Clear the state
	return h.state.Zero()
}

/*
GetHash query the computed hash
*/
func (h *sodiumHasher) GetHash() []byte {
	return h.hash
}
