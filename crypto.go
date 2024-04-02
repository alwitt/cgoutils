package cgoutils

import "unsafe"

// Crypto wrapper object for performing
type Crypto interface {
	/*
		AllocateCryptoCSlice allocate a libsodium secure memory backed slice

			@param length uint64 - length of the array
			@return CSlice object
	*/
	AllocateCryptoCSlice(length int) (CryptoCSlice, error)
}

// CryptoCSlice a CSlice specifically designed for use with crypto libraries. They
// implement additional features.
type CryptoCSlice interface {
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
}
