package crypto

import (
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"io"
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

	// GetRNGReader similar to various `rand.Reader` utilities
	GetRNGReader() io.Reader

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
	// Public Key Crypto

	/*
		CreateED25519SelfSignedCA create an ED25519 self-signed certificate authority

			@param ctxt context.Context - calling context
			@param caParams CertParams - CA cert generation parameters
			@returns the ed25519 private key and the associated certificate
	*/
	CreateED25519SelfSignedCA(
		ctxt context.Context, caParams CertParams,
	) (ed25519.PrivateKey, []byte, error)

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
		ParseRSAPrivateKeyFromPEM parse a PEM for a RSA private key in PKCS1 or PKCS8 format

			@param ctxt context.Context - calling context
			@param keyPem string - the PEM string
			@returns the parsed RSA private key
	*/
	ParseRSAPrivateKeyFromPEM(
		ctxt context.Context, keyPem string,
	) (*rsa.PrivateKey, error)

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
	ReadED25519PublicKeyFromCert(
		ctxt context.Context, cert *x509.Certificate,
	) (ed25519.PublicKey, error)

	/*
		ReadRSAPublicKeyFromCert read the RSA public from certificate

			@param ctxt context.Context - calling context
			@param cert *x509.Certificate - certificate
			@returns the RSA public key
	*/
	ReadRSAPublicKeyFromCert(
		ctxt context.Context, cert *x509.Certificate,
	) (*rsa.PublicKey, error)

	/*
		RSAEncrypt wrapper function, encrypt plain text using RSA public key

			@param ctxt context.Context - calling context
			@param plainText []byte - plain text being encrypted
			@param pubKey *rsa.PublicKey - RSA public key
			@param dataLabel []byte - contain arbitrary data that will not be encrypted, but which gives
			    important context to the message. Similar in concept to the additional data of AEAD.
			    Leave empty if not used.
			@returns encrypted cipher text
	*/
	RSAEncrypt(
		ctxt context.Context, plainText []byte, pubKey *rsa.PublicKey, dataLabel []byte,
	) ([]byte, error)

	/*
		RSADecrypt wrapper function, decrypt cipher text using RSA private key

			@param ctxt context.Context - calling context
			@param cipherText []byte - cipher text being decrypted
			@param privKey *rsa.PrivateKey - RSA private key
			@param dataLabel []byte - contain arbitrary data that will not be decrypted, but which gives
			    important context to the message. Similar in concept to the additional data of AEAD.
			    Leave empty if not used.
			@returns decrypted plain text
	*/
	RSADecrypt(
		ctxt context.Context, cipherText []byte, privKey *rsa.PrivateKey, dataLabel []byte,
	) ([]byte, error)

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
