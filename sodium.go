package cgoutils

// #cgo CFLAGS: -Wall
// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"

import (
	"context"
	"fmt"
	"runtime"
	"unsafe"

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

// ======================================================================================
// Utilities

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

// ======================================================================================
// RNG

/*
GetRandomBuf get a buffer of random data with the specified length

	@param ctxt context.Context - calling context
	@param length int - the length of the buffer to fill
*/
func (c *sodiumCrypto) GetRandomBuf(ctxt context.Context, length int) (CryptoCSlice, error) {
	logTags := c.GetLogTagsForContext(ctxt)
	logTags["length"] = length

	// Prepare new buffer
	newBuf, err := c.AllocateCryptoCSlice(length)
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

// ======================================================================================
// libsodium hashing
//
// It uses BLAKE2b as the hashing algorithm

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

// ======================================================================================
// libsodium secure memory

// sodiumCSlice slice backed up by libsodium memory management
type sodiumCSlice struct {
	// length length of the slice
	length int
	// core pointer to the actual C array
	core *C.void
}

// freeSodiumCSlice support de-allocation function for sodiumCSlice
func freeSodiumCSlice(b *sodiumCSlice) {
	if err := b.release(); err != nil {
		log.WithError(err).Errorf("Failed to free core C array of slice")
	}
}

// allocate allocate the core buffer in libsodium
func (b *sodiumCSlice) allocate(length int) error {
	if b.core != nil {
		return fmt.Errorf("still pointing at a previously allocated array")
	}

	if length < 0 {
		return fmt.Errorf("can't allocated array with length < 0")
	}

	// get the new buffer from libsodium
	b.core = (*C.void)(C.sodium_malloc(C.size_t(length)))
	if b.core == nil {
		return fmt.Errorf("failed to allocated libsodium buffer of length %d", length)
	}
	log.
		WithField("libsodium-ptr", unsafe.Pointer(b.core)).
		WithField("len", length).
		Debug("Allocated new C array")

	b.length = length

	// Record callback to automate memory clean up
	runtime.SetFinalizer(b, freeSodiumCSlice)
	return nil
}

// release release the core buffer in libsodium
func (b *sodiumCSlice) release() error {
	if b.core == nil {
		return fmt.Errorf("slice is not allocated")
	}

	// Release the buffer in C
	C.sodium_free(unsafe.Pointer(b.core))
	log.
		WithField("libsodium-ptr", unsafe.Pointer(b.core)).
		WithField("len", b.length).
		Debug("Freed C array")

	// Null all pointers
	b.core = nil
	b.length = -1

	return nil
}

/*
Zero zero the contents of the buffer
*/
func (b *sodiumCSlice) Zero() error {
	if b.core == nil {
		return fmt.Errorf("slice is not allocated")
	}

	// Zero the buffer in C
	C.sodium_memzero(unsafe.Pointer(b.core), C.size_t(b.length))
	log.
		WithField("libsodium-ptr", unsafe.Pointer(b.core)).
		WithField("len", b.length).
		Debug("Zeroed C array")

	return nil
}

/*
GetLen return the length of slice

	@returns the slice length
*/
func (b *sodiumCSlice) GetLen() (int, error) {
	if b.core == nil {
		return -1, fmt.Errorf("slice is not allocated")
	}
	return b.length, nil
}

/*
GetSlice return reference to the slice

	@returns the managed slice
*/
func (b *sodiumCSlice) GetSlice() ([]byte, error) {
	if b.core == nil {
		return nil, fmt.Errorf("slice is not allocated")
	}
	return unsafe.Slice((*byte)(unsafe.Pointer(b.core)), b.length), nil
}

/*
GetCArray return reference to the C buffer

	@returns the C slice
*/
func (b *sodiumCSlice) GetCArray() (unsafe.Pointer, error) {
	if b.core == nil {
		return nil, fmt.Errorf("slice is not allocated")
	}
	return unsafe.Pointer(b.core), nil
}
