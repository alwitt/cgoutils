package cgoutils

// #include <stdlib.h>
import "C"

import (
	"fmt"
	"runtime"
	"unsafe"

	"github.com/apex/log"
)

// CSlice a slice object backed by memory allocated in C side.
//
// All implementations must register a de-allocation function with `runtime.SetFinalizer`
type CSlice interface {
	/*
		GetLen return the length of slice

			@returns the slice length
	*/
	GetLen() (int, error)

	/*
		GetSlice return reference to the slice

			@returns the managed slice
	*/
	GetSlice() ([]byte, error)
}

// basicCSlice slice backed up by standard C buffer managed by `malloc` and `free`
type basicCSlice struct {
	// len length of the slice
	len int
	// core pointer to the actual C array
	core *C.void
	// asSlice Go slice reference to the C array for use in Go
	asSlice []byte
}

// freeBasicCSlice support de-allocation function for basicCSlice
func freeBasicCSlice(b *basicCSlice) {
	if err := b.release(); err != nil {
		log.WithError(err).Errorf("Failed to free core C array of slice")
	}
}

// allocate allocate the core buffer in C
func (b *basicCSlice) allocate(len int) error {
	if b.core != nil || b.asSlice != nil {
		return fmt.Errorf("still pointing at a previously allocated array")
	}

	if len < 0 {
		return fmt.Errorf("can't allocated array with length < 0")
	}

	// get the new buffer from C
	b.core = (*C.void)(C.malloc(C.size_t(len)))
	if b.core == nil {
		return fmt.Errorf("failed to allocated C buffer of length %d", len)
	}
	log.
		WithField("ptr", unsafe.Pointer(b.core)).
		WithField("len", len).
		Debug("Allocated new C array")

	// Convert to Slice
	b.asSlice = C.GoBytes(unsafe.Pointer(b.core), C.int(len))
	if b.asSlice == nil {
		return fmt.Errorf("failed to convert C buffer to Go slice reference")
	}
	log.
		WithField("ptr", unsafe.Pointer(b.core)).
		WithField("len", len).
		Debug("Converted C array to Go slice")

	b.len = len

	// Record callback to automate memory clean up
	runtime.SetFinalizer(b, freeBasicCSlice)
	return nil
}

// allocate release the core buffer in c
func (b *basicCSlice) release() error {
	if b.core == nil || b.asSlice == nil {
		return fmt.Errorf("slice is not allocated")
	}

	// Release the buffer in C
	C.free(unsafe.Pointer(b.core))
	log.
		WithField("ptr", unsafe.Pointer(b.core)).
		WithField("len", b.len).
		Debug("Freed C array")

	// Null all pointers
	b.asSlice = nil
	b.core = nil
	b.len = -1

	return nil
}

/*
GetLen return the length of slice

	@returns the slice length
*/
func (b *basicCSlice) GetLen() (int, error) {
	if b.core == nil || b.asSlice == nil {
		return -1, fmt.Errorf("slice is not allocated")
	}
	return b.len, nil
}

/*
GetSlice return reference to the slice

	@returns the managed slice
*/
func (b *basicCSlice) GetSlice() ([]byte, error) {
	if b.core == nil || b.asSlice == nil {
		return nil, fmt.Errorf("slice is not allocated")
	}
	return b.asSlice, nil
}

/*
AllocateBasicCSlice allocate a basic C array backed slice

	@param len uint64 - length of the array
	@return CSlice object
*/
func AllocateBasicCSlice(len int) (CSlice, error) {
	instance := &basicCSlice{core: nil, asSlice: nil}
	return instance, instance.allocate(len)
}
