// Package common - common utility structs and functions
package common //revive:disable-line:var-naming

// #include <stdlib.h>
// #include <stdint.h>
import "C"

import (
	"fmt"
	"runtime"
	"unsafe"

	"github.com/alwitt/goutils"
	"github.com/apex/log"
)

// CSlice a slice object backed by "void*" array allocated in C side.
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

	/*
		GetCArray return reference to the C buffer

			@returns the C slice
	*/
	GetCArray() (unsafe.Pointer, error)
}

// basicCSlice slice backed up by standard C buffer managed by `malloc` and `free`
type basicCSlice struct {
	// length length of the slice
	length int
	// core pointer to the actual C array
	core *C.void
}

// freeBasicCSlice support de-allocation function for basicCSlice
func freeBasicCSlice(b *basicCSlice) {
	if err := b.release(); err != nil {
		log.WithError(err).Errorf("Failed to free core C array of slice")
	}
}

// allocate allocate the core buffer in C
func (b *basicCSlice) allocate(length int) error {
	if b.core != nil {
		return goutils.NewConsistencyError(
			"still pointing at a previously allocated array", nil, true,
		)
	}

	if length < 0 {
		return goutils.NewBadInputError("can't allocated array with length < 0", nil, true)
	}

	// get the new buffer from C
	b.core = (*C.void)(C.malloc(C.size_t(length)))
	if b.core == nil {
		return NewCError(
			fmt.Sprintf("failed to allocated C buffer of length %d", length), nil, true,
		)
	}
	log.
		WithField("ptr", unsafe.Pointer(b.core)).
		WithField("len", length).
		Debug("Allocated new C array")

	b.length = length

	// Record callback to automate memory clean up
	runtime.SetFinalizer(b, freeBasicCSlice)
	return nil
}

// release release the core buffer in c
func (b *basicCSlice) release() error {
	if b.core == nil {
		return goutils.NewConsistencyError("slice is not allocated", nil, true)
	}

	// Release the buffer in C
	C.free(unsafe.Pointer(b.core))
	log.
		WithField("ptr", unsafe.Pointer(b.core)).
		WithField("len", b.length).
		Debug("Freed C array")

	// Null all pointers
	b.core = nil
	b.length = -1

	return nil
}

/*
GetLen return the length of slice

	@returns the slice length
*/
func (b *basicCSlice) GetLen() (int, error) {
	if b.core == nil {
		return -1, goutils.NewConsistencyError("slice is not allocated", nil, true)
	}
	return b.length, nil
}

/*
GetSlice return reference to the slice

	@returns the managed slice
*/
func (b *basicCSlice) GetSlice() ([]byte, error) {
	if b.core == nil {
		return nil, goutils.NewConsistencyError("slice is not allocated", nil, true)
	}
	return unsafe.Slice((*byte)(unsafe.Pointer(b.core)), b.length), nil
}

/*
GetCArray return reference to the C buffer

	@returns the C slice
*/
func (b *basicCSlice) GetCArray() (unsafe.Pointer, error) {
	if b.core == nil {
		return nil, goutils.NewConsistencyError("slice is not allocated", nil, true)
	}
	return unsafe.Pointer(b.core), nil
}

/*
AllocateBasicCSlice allocate a basic C array backed slice

	@param length uint64 - length of the array
	@return CSlice object
*/
func AllocateBasicCSlice(length int) (CSlice, error) {
	instance := &basicCSlice{core: nil}
	return instance, instance.allocate(length)
}
