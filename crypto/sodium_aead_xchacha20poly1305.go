package crypto

// #include <stdlib.h>
// #include <sodium.h>
import "C"
import (
	"context"
	"fmt"
	"unsafe"
)

// sodiumXChaCha20Poly1305 implements AEAD using XChaCha20-Poly1305
type sodiumXChaCha20Poly1305 struct {
	core  Engine
	nonce SecureCSlice
	key   SecureCSlice
}

/*
ExpectedKeyLen get the expected encryption key len

	@returns expected encryption key len
*/
func (a *sodiumXChaCha20Poly1305) ExpectedKeyLen() int {
	return C.crypto_aead_xchacha20poly1305_ietf_KEYBYTES
}

/*
ExpectedNonceLen get the expected nonce len

	@returns expected nonce len
*/
func (a *sodiumXChaCha20Poly1305) ExpectedNonceLen() int {
	return C.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
}

/*
SetKey set the encryption key

	@param key SecureCSlice - the encryption key
*/
func (a *sodiumXChaCha20Poly1305) SetKey(key SecureCSlice) error {
	if length, err := key.GetLen(); err != nil {
		return err
	} else if length != a.ExpectedKeyLen() {
		return fmt.Errorf(
			"incorrect key length for XChaCha20-Poly1305: %d =/= %d", length, a.ExpectedKeyLen(),
		)
	}
	a.key = key
	return nil
}

/*
SetNonce set the nonce

	@param nonce SecureCSlice - the nonce
*/
func (a *sodiumXChaCha20Poly1305) SetNonce(nonce SecureCSlice) error {
	if length, err := nonce.GetLen(); err != nil {
		return err
	} else if length != a.ExpectedNonceLen() {
		return fmt.Errorf(
			"incorrect nonce length for XChaCha20-Poly1305: %d =/= %d", length, a.ExpectedNonceLen(),
		)
	}
	a.nonce = nonce
	return nil
}

/*
ResetNonce reset the AEAD nonce value

	@param ctxt context.Context - calling context
*/
func (a *sodiumXChaCha20Poly1305) ResetNonce(ctxt context.Context) error {
	nonce, err := a.core.GetRandomBuf(ctxt, a.ExpectedNonceLen())
	if err != nil {
		return err
	}
	a.nonce = nonce
	return nil
}

/*
Type get the AEAD implementation

	@returns AEAD type
*/
func (a *sodiumXChaCha20Poly1305) Type() AEADTypeEnum {
	return AEADTypeXChaCha20Poly1305
}

/*
Nonce return the current nonce value

	@returns the nonce
*/
func (a *sodiumXChaCha20Poly1305) Nonce() SecureCSlice {
	return a.nonce
}

/*
ExpectedCipherLen compute the expected cipher text len given the plain text length

	@returns the expected cipher text length
*/
func (a *sodiumXChaCha20Poly1305) ExpectedCipherLen(plainTextLen int64) int64 {
	return plainTextLen + C.crypto_aead_xchacha20poly1305_ietf_ABYTES
}

/*
ExpectedPlainTextLen compute the expected plain text len given the cipher text length

	@returns the expected plain text length
*/
func (a *sodiumXChaCha20Poly1305) ExpectedPlainTextLen(cipherLen int64) int64 {
	return cipherLen - C.crypto_aead_xchacha20poly1305_ietf_ABYTES
}

/*
Seal encrypt plain text with associated additional data.

	@param ctxt context.Context - calling context
	@param msgIndex int64 - the message index within a stream
	@param plainText []byte - the plain text to encrypt
	@param additional []byte - the associated additional data
	@param cipherText []byte - the output buffer for the cipher text
*/
func (a *sodiumXChaCha20Poly1305) Seal(
	_ context.Context, msgIndex int64, plainText []byte, additional []byte, cipherText []byte,
) error {
	plainLen := int64(len(plainText))
	additionalLen := int64(len(additional))

	// Make a copy of the nonce
	theNonce, err := getAEADNonceForIndex(msgIndex, a.core, a)
	if err != nil {
		return err
	}

	// Verify output buffer for cipher text
	cipherLen := a.ExpectedCipherLen(int64(plainLen))
	{
		outputLen := int64(len(cipherText))
		if outputLen != cipherLen {
			return fmt.Errorf("cipher text output buffer wrong size: %d =/= %d", outputLen, cipherLen)
		}
	}

	// Grab relevant pointers
	cipherTextCore := unsafe.Pointer(&cipherText[0])
	keyCore, err := a.key.GetCArray()
	if err != nil {
		return err
	}
	nonceCore, err := theNonce.GetCArray()
	if err != nil {
		return err
	}
	plainTextPtr := unsafe.Pointer(&plainText[0])
	var additionalPtr unsafe.Pointer
	if additional != nil {
		additionalPtr = unsafe.Pointer(&additional[0])
	} else {
		additionalPtr = nil
	}

	// Encrypt the msg with additional data
	resp := C.crypto_aead_xchacha20poly1305_ietf_encrypt(
		(*C.uchar)(cipherTextCore),
		(*C.ulonglong)(nil),
		(*C.uchar)(plainTextPtr),
		C.ulonglong(plainLen),
		(*C.uchar)(additionalPtr),
		C.ulonglong(additionalLen),
		(*C.uchar)(nil),
		(*C.uchar)(nonceCore),
		(*C.uchar)(keyCore),
	)
	if resp != 0 {
		err := fmt.Errorf("encryption failed with %d", resp)
		return err
	}

	return nil
}

/*
Unseal decrypt cipher text with associated additional data.

	@param ctxt context.Context - calling context
	@param msgIndex int64 - the message index within a stream
	@param cipherText []byte - the cipher text to decrypt
	@param additional []byte - the associated additional data
	@param plainText []byte - the output buffer for plain text
*/
func (a *sodiumXChaCha20Poly1305) Unseal(
	_ context.Context, msgIndex int64, cipherText []byte, additional []byte, plainText []byte,
) error {
	cipherLen := int64(len(cipherText))
	additionalLen := int64(len(additional))

	// Make a copy of the nonce
	theNonce, err := getAEADNonceForIndex(msgIndex, a.core, a)
	if err != nil {
		return err
	}

	// Verify output for plain text
	plainLen := a.ExpectedPlainTextLen(int64(cipherLen))
	{
		outputLen := int64(len(plainText))
		if outputLen != plainLen {
			return fmt.Errorf("plain text output buffer wrong size: %d =/= %d", outputLen, plainLen)
		}
	}

	// Grab relevant pointers
	cipherTextCore := unsafe.Pointer(&cipherText[0])
	keyCore, err := a.key.GetCArray()
	if err != nil {
		return err
	}
	nonceCore, err := theNonce.GetCArray()
	if err != nil {
		return err
	}
	plainTextPtr := unsafe.Pointer(&plainText[0])
	var additionalPtr unsafe.Pointer
	if additional != nil {
		additionalPtr = unsafe.Pointer(&additional[0])
	} else {
		additionalPtr = nil
	}

	// Decrypt the msg with additional data
	resp := C.crypto_aead_xchacha20poly1305_ietf_decrypt(
		(*C.uchar)(plainTextPtr),
		(*C.ulonglong)(nil),
		(*C.uchar)(nil),
		(*C.uchar)(cipherTextCore),
		C.ulonglong(cipherLen),
		(*C.uchar)(additionalPtr),
		C.ulonglong(additionalLen),
		(*C.uchar)(nonceCore),
		(*C.uchar)(keyCore),
	)
	if resp != 0 {
		err := fmt.Errorf("decryption failed with %d", resp)
		return err
	}

	return nil
}
