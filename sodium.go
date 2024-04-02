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
// libsodium PBKDF
//
// It uses Argon2ID13

const (
	// SodiumPBKDFOutputMin minimum PBKDF target key length
	SodiumPBKDFOutputMin = C.crypto_pwhash_BYTES_MIN
	// SodiumPBKDFOutputMax maximum PBKDF target key length
	SodiumPBKDFOutputMax = C.crypto_pwhash_BYTES_MAX

	// SodiumPBKDFPasswdMin minimum PBKDF input password length
	SodiumPBKDFPasswdMin = C.crypto_pwhash_PASSWD_MIN

	// SodiumPBKDFOpsLimitMin minimum PBKDF OPS limit
	SodiumPBKDFOpsLimitMin = C.crypto_pwhash_OPSLIMIT_MIN
	// SodiumPBKDFOpsLimitFast fast PBKDF OPS limit
	SodiumPBKDFOpsLimitFast = C.crypto_pwhash_OPSLIMIT_INTERACTIVE
	// SodiumPBKDFOpsLimitMed medium PBKDF OPS limit
	SodiumPBKDFOpsLimitMed = C.crypto_pwhash_OPSLIMIT_MODERATE
	// SodiumPBKDFOpsLimitSlow slow PBKDF OPS limit
	SodiumPBKDFOpsLimitSlow = C.crypto_pwhash_OPSLIMIT_SENSITIVE
	// SodiumPBKDFOpsLimitMax maximum PBKDF OPS limit
	SodiumPBKDFOpsLimitMax = C.crypto_pwhash_OPSLIMIT_MAX

	// SodiumPBKDFMemLimitMin minimum PBKDF MEM limit
	SodiumPBKDFMemLimitMin = C.crypto_pwhash_MEMLIMIT_MIN
	// SodiumPBKDFMemLimitFast fast PBKDF MEM limit
	SodiumPBKDFMemLimitFast = C.crypto_pwhash_MEMLIMIT_INTERACTIVE
	// SodiumPBKDFMemLimitMed medium PBKDF MEM limit
	SodiumPBKDFMemLimitMed = C.crypto_pwhash_MEMLIMIT_MODERATE
	// SodiumPBKDFMemLimitSlow slow PBKDF MEM limit
	SodiumPBKDFMemLimitSlow = C.crypto_pwhash_MEMLIMIT_SENSITIVE
	// SodiumPBKDFMemLimitMax maximum PBKDF MEM limit
	SodiumPBKDFMemLimitMax = C.crypto_pwhash_MEMLIMIT_MAX
)

/*
GetPBKDFSalt get a salt for use with PBKDF

	@param ctxt context.Context - calling context
	@returns new salt
*/
func (c *sodiumCrypto) GetPBKDFSalt(ctxt context.Context) (CryptoCSlice, error) {
	return c.GetRandomBuf(ctxt, C.crypto_pwhash_SALTBYTES)
}

/*
PBKDF perform password based key derivation

	@param ctxt context.Context - calling context
	@param passwd []byte - starting password
	@param salt CryptoCSlice - associated salt
	@param opsLimit uint64 - computation complexity limit
	@param memLimit uint64 - memory complexity limit (in bytes)
	@param outLength uint64 - target output key length
	@returns the generated key
*/
func (c *sodiumCrypto) PBKDF(
	ctxt context.Context,
	passwd []byte,
	salt CryptoCSlice,
	opsLimit uint64,
	memLimit uint64,
	outLength int,
) (CryptoCSlice, error) {
	logTags := c.GetLogTagsForContext(ctxt)

	// Verify the inputs
	if len(passwd) < C.crypto_pwhash_PASSWD_MIN || len(passwd) > C.crypto_pwhash_PASSWD_MAX {
		err := fmt.Errorf("password failed length constraint")
		log.WithError(err).WithFields(logTags).Error("Key derivation input failure")
		return nil, err
	}
	if saltLen, err := salt.GetLen(); err != nil {
		log.WithError(err).WithFields(logTags).Error("Unable to read salt length")
		return nil, err
	} else if saltLen != C.crypto_pwhash_SALTBYTES {
		err := fmt.Errorf("salt failed length constraint")
		log.WithError(err).WithFields(logTags).Error("Key derivation input failure")
		return nil, err
	}
	if opsLimit < C.crypto_pwhash_OPSLIMIT_MIN || opsLimit > C.crypto_pwhash_OPSLIMIT_MAX {
		err := fmt.Errorf("computation complexity limit outside of supported range")
		log.WithError(err).WithFields(logTags).Error("Key derivation input failure")
		return nil, err
	}
	if memLimit < C.crypto_pwhash_MEMLIMIT_MIN || memLimit > C.crypto_pwhash_MEMLIMIT_MAX {
		err := fmt.Errorf("memory complexity limit outside of supported range")
		log.WithError(err).WithFields(logTags).Error("Key derivation input failure")
		return nil, err
	}
	if outLength < C.crypto_pwhash_BYTES_MIN || outLength > C.crypto_pwhash_BYTES_MAX {
		err := fmt.Errorf("target key length outside of supported range")
		log.WithError(err).WithFields(logTags).Error("Key derivation input failure")
		return nil, err
	}

	// Generate output buffer
	output, err := c.AllocateCryptoCSlice(outLength)
	if err != nil {
		log.WithError(err).WithFields(logTags).Error("Failed to allocate output buffer")
		return nil, err
	}

	outputPtr, err := output.GetCArray()
	if err != nil {
		log.WithError(err).WithFields(logTags).Error("Unable to get output buffer pointer")
		return nil, err
	}

	saltPtr, err := salt.GetCArray()
	if err != nil {
		log.WithError(err).WithFields(logTags).Error("Unable to get salt pointer")
		return nil, err
	}

	resp := int(C.crypto_pwhash(
		(*C.uchar)(outputPtr),
		C.ulonglong(outLength),
		(*C.char)(unsafe.Pointer(&passwd[0])),
		C.ulonglong(len(passwd)),
		(*C.uchar)(saltPtr),
		C.ulonglong(opsLimit),
		C.size_t(memLimit),
		C.crypto_pwhash_ALG_ARGON2ID13,
	))
	if resp != 0 {
		err := fmt.Errorf("key derivation failed with %d", resp)
		return nil, err
	}

	return output, nil
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
