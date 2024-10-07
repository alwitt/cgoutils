package crypto

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"math/big"
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

	// ------------------------------------------------------------------------------------
	// ED25519 Public Key Crypto

	/*
		CreateED25519CSR create an ED25519 private key and associated certificate signing request

			@param ctxt context.Context - calling context
			@param csrParams CertSigningRequestParams - CSR generation parameters
			@returns the ed25519 private key and the associated certificate signing request
	*/
	CreateED25519CSR(
		ctxt context.Context, csrParams CertSigningRequestParams,
	) (ed25519.PrivateKey, []byte, error)

	/*
		ParseCertificateFromPEM parse a PEM block for a certificate

			@param ctxt context.Context - calling context
			@param certPem string - the PEM string
			@returns the parsed certificate
	*/
	ParseCertificateFromPEM(ctxt context.Context, certPem string) (*x509.Certificate, error)

	/*
		ReadED25519PublicKeyFromCert read the ED25519 public from certificate

			@param ctxt context.Context - calling context
			@param cert *x509.Certificate - certificate
			@returns the ED25519 public key
	*/
	ReadED25519PublicKeyFromCert(_ context.Context, cert *x509.Certificate) (ed25519.PublicKey, error)

	// ------------------------------------------------------------------------------------
	// ECDH

	/*
		NewECDHKeyPair generate a new ECDH key pair

			@param ctxt context.Context - calling context
			@returns the generated key pair
	*/
	NewECDHKeyPair(ctxt context.Context) (ECDHKeyPair, error)

	/*
		ComputeClientECDHSessionKeys run client side ECDH and generate client side ECDH session keys

			@param ctxt context.Context - calling context
			@param clientKeys ECDHKeyPair - client ECDH key pair
			@param serverPublic SecureCSlice - server public key
			@returns client side ECDH session keys
	*/
	ComputeClientECDHSessionKeys(
		ctxt context.Context, clientKeys ECDHKeyPair, serverPublic SecureCSlice,
	) (ECDHSessionKeys, error)

	/*
		ComputeServerECDHSessionKeys run server side ECDH and generate server side ECDH session keys

			@param ctxt context.Context - calling context
			@param serverKeys ECDHKeyPair - server ECDH key pair
			@param clientPublic SecureCSlice - client public key
			@returns server side ECDH session keys
	*/
	ComputeServerECDHSessionKeys(
		ctxt context.Context, serverKeys ECDHKeyPair, clientPublic SecureCSlice,
	) (ECDHSessionKeys, error)

	// ------------------------------------------------------------------------------------
	// AEAD

	/*
		GetAEAD define a new AEAD instance

			@param ctxt context.Context - calling context
			@param aeadType AEADTypeEnum - the AEAD implementation to use
			@returns the AEAD generator
	*/
	GetAEAD(ctxt context.Context, aeadType AEADTypeEnum) (AEAD, error)
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

// AEAD a AEAD engine
type AEAD interface {
	/*
		ExpectedKeyLen get the expected encryption key len

			@returns expected encryption key len
	*/
	ExpectedKeyLen() int

	/*
		SetKey set the encryption key

			@param key SecureCSlice - the encryption key
	*/
	SetKey(key SecureCSlice) error

	/*
		ExpectedNonceLen get the expected nonce len

			@returns expected nonce len
	*/
	ExpectedNonceLen() int

	/*
		SetNonce set the nonce

			@param nonce SecureCSlice - the nonce
	*/
	SetNonce(nonce SecureCSlice) error

	/*
		ResetNonce reset the AEAD nonce value

			@param ctxt context.Context - calling context
	*/
	ResetNonce(ctxt context.Context) error

	/*
		Type get the AEAD implementation

			@returns AEAD type
	*/
	Type() AEADTypeEnum

	/*
		Nonce return the current nonce value

			@returns the nonce
	*/
	Nonce() SecureCSlice

	/*
		ExpectedCipherLen compute the expected cipher text len given the plain text length

			@returns the expected cipher text length
	*/
	ExpectedCipherLen(plainTextLen int64) int64

	/*
		ExpectedPlainTextLen compute the expected plain text len given the cipher text length

			@returns the expected plain text length
	*/
	ExpectedPlainTextLen(cipherLen int64) int64

	/*
		Seal encrypt plain text with associated additional data.

			@param ctxt context.Context - calling context
			@param msgIndex int64 - the message index within a stream
			@param plainText []byte - the plain text to encrypt
			@param additional []byte - the associated additional data
			@param cipherText []byte - the output buffer for the cipher text
	*/
	Seal(
		ctxt context.Context, msgIndex int64, plainText []byte, additional []byte, cipherText []byte,
	) error

	/*
		Unseal decrypt cipher text with associated additional data.

			@param ctxt context.Context - calling context
			@param msgIndex int64 - the message index within a stream
			@param cipherText []byte - the cipher text to decrypt
			@param additional []byte - the associated additional data
			@param plainText []byte - the output buffer for plain text
	*/
	Unseal(
		ctxt context.Context, msgIndex int64, cipherText []byte, additional []byte, plainText []byte,
	) error
}
