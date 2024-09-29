package crypto

import (
	"context"
	"unsafe"
)

// Engine wrapper object for performing cryptographic operations on data
type Engine interface {
	/*
		AllocateSecureCSlice allocate a libsodium secure memory backed slice

			@param length uint64 - length of the array
			@return CSlice object
	*/
	AllocateSecureCSlice(length int) (SecureCSlice, error)

	// ------------------------------------------------------------------------------------
	// RNG

	/*
		GetRandomBuf get a buffer of random data with the specified length

			@param ctxt context.Context - calling context
			@param length int - the length of the buffer to fill
	*/
	GetRandomBuf(ctxt context.Context, length int) (SecureCSlice, error)

	// ------------------------------------------------------------------------------------
	// Hashing

	/*
		GetHasherKey get a key for the cryptographic hasher

			@param ctxt context.Context - calling context
			@returns new key
	*/
	GetHasherKey(ctxt context.Context) (SecureCSlice, error)

	/*
		GetHasher get a libsodium cryptographic hasher

			@param ctxt context.Context - calling context
			@param key CryptoCSlice - for keyed hashing function
			@returns the hasher
	*/
	GetHasher(ctxt context.Context, key SecureCSlice) (Hasher, error)

	// ------------------------------------------------------------------------------------
	// PBKDF

	/*
		GetPBKDFSalt get a salt for use with PBKDF

			@param ctxt context.Context - calling context
			@returns new salt
	*/
	GetPBKDFSalt(ctxt context.Context) (SecureCSlice, error)

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
		salt SecureCSlice,
		opsLimit uint64,
		memLimit uint64,
		outLength int,
	) (SecureCSlice, error)
}

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
}

// Hasher a cryptographic hash generator
type Hasher interface {
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
