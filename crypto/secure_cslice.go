package crypto

import (
	"math/big"
	"unsafe"
)

// SecureCSlice a CSlice specifically designed for use with crypto libraries. They
// implement additional features.
type SecureCSlice interface {
	/*
		Zero zero the contents of the buffer
	*/
	Zero() error

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

	/*
		IncrementValue treat the content of the buffer as a large number, and increment by one
	*/
	IncrementValue() error

	/*
		AddValue treat the content of the buffer as a large number, and add another value to it.

			@param value *big.Int - the value to add to current content of the buffer
	*/
	AddValue(value *big.Int) error
}
