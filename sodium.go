package cgoutils

// #cgo CFLAGS: -Wall
// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"

import (
	"fmt"
	"runtime"
	"unsafe"

	"github.com/apex/log"
)

// sodiumCrypto `libsodium` wrapper client which implements Crypto
type sodiumCrypto struct{}

/*
NewSodiumCrypto define a `libsodium` backed Crypto object.

	@returns new Crypto object
*/
func NewSodiumCrypto() (Crypto, error) {
	instance := &sodiumCrypto{}
	return instance, instance.init()
}

// ======================================================================================
// Utilities

// init initialize `libsodium` for use
func (c *sodiumCrypto) init() error {
	if int(C.sodium_init()) == -1 {
		return fmt.Errorf("failed to initialize 'libsodium'")
	}
	if int(C.sodium_init()) == 1 {
		log.Debug("libsodium already initialized")
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
