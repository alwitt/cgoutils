package cgoutils

import (
	"context"
	"unsafe"
)

// Crypto wrapper object for performing cryptographic operations on data
type Crypto interface {
	/*
		AllocateCryptoCSlice allocate a libsodium secure memory backed slice

			@param length uint64 - length of the array
			@return CSlice object
	*/
	AllocateCryptoCSlice(length int) (CryptoCSlice, error)

	// ------------------------------------------------------------------------------------
	// RNG

	/*
		GetRandomBuf get a buffer of random data with the specified length

			@param ctxt context.Context - calling context
			@param length int - the length of the buffer to fill
	*/
	GetRandomBuf(ctxt context.Context, length int) (CryptoCSlice, error)

	// ------------------------------------------------------------------------------------
	// Hashing

	/*
		GetHasherKey get a key for the cryptographic hasher

			@param ctxt context.Context - calling context
			@returns new key
	*/
	GetHasherKey(ctxt context.Context) (CryptoCSlice, error)

	/*
		GetHasher get a libsodium cryptographic hasher

			@param ctxt context.Context - calling context
			@param key CryptoCSlice - for keyed hashing function
			@returns the hasher
	*/
	GetHasher(ctxt context.Context, key CryptoCSlice) (CryptoHasher, error)

	// ------------------------------------------------------------------------------------
	// PBKDF

	/*
		GetPBKDFSalt get a salt for use with PBKDF

			@param ctxt context.Context - calling context
			@returns new salt
	*/
	GetPBKDFSalt(ctxt context.Context) (CryptoCSlice, error)

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
	PBKDF(
		ctxt context.Context,
		passwd []byte,
		salt CryptoCSlice,
		opsLimit uint64,
		memLimit uint64,
		outLength int,
	) (CryptoCSlice, error)
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

// CryptoHasher a cryptographic hash generator
type CryptoHasher interface {
	/*
		Update update the hash compute with new data

			@param buf []byte - new data
	*/
	Update(buf []byte) error

	/*
		Finalize finalize the hash computation
	*/
	Finalize() error

	/*
		GetHash query the computed hash
	*/
	GetHash() []byte
}
