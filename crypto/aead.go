package crypto

import "context"

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
