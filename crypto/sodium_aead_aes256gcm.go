package crypto

// #include <stdlib.h>
// #include <sodium.h>
import "C"
import (
	"context"
	"fmt"
	"unsafe"
)

// sodiumAES256GCM implements AEAD using AES256-GCM
type sodiumAES256GCM struct {
	core  Engine
	nonce SecureCSlice
	key   SecureCSlice
}

/*
newAES256GCM define a AES256-GCM based AEAD

	@param ctxt context.Context - calling context
	@returns new AES256-GCM based AEAD generator
*/
func (c *engineImpl) newAES256GCM(_ context.Context) (*sodiumAES256GCM, error) {
	// Verify the system support AES256-GCM
	if C.crypto_aead_aes256gcm_is_available() == 0 {
		return nil, fmt.Errorf("system does not support AES256-GCM in hardware")
	}

	return &sodiumAES256GCM{core: c}, nil
}

/*
ExpectedKeyLen get the expected encryption key len

	@returns expected encryption key len
*/
func (a *sodiumAES256GCM) ExpectedKeyLen() int {
	return C.crypto_aead_aes256gcm_KEYBYTES
}

/*
SetKey set the encryption key

	@param key SecureCSlice - the encryption key
*/
func (a *sodiumAES256GCM) SetKey(key SecureCSlice) error {
	if len, err := key.GetLen(); err != nil {
		return err
	} else if len != a.ExpectedKeyLen() {
		return fmt.Errorf(
			"incorrect key length for AES256-GCM: %d =/= %d", len, a.ExpectedKeyLen(),
		)
	}
	a.key = key
	return nil
}

/*
ExpectedNonceLen get the expected nonce len

	@returns expected nonce len
*/
func (a *sodiumAES256GCM) ExpectedNonceLen() int {
	return C.crypto_aead_aes256gcm_NPUBBYTES
}

/*
SetNonce set the nonce

	@param nonce SecureCSlice - the nonce
*/
func (a *sodiumAES256GCM) SetNonce(nonce SecureCSlice) error {
	if len, err := nonce.GetLen(); err != nil {
		return err
	} else if len != a.ExpectedNonceLen() {
		return fmt.Errorf(
			"incorrect nonce length for AES256-GCM: %d =/= %d", len, a.ExpectedNonceLen(),
		)
	}
	a.nonce = nonce
	return nil
}

/*
ResetNonce reset the AEAD nonce value

	@param ctxt context.Context - calling context
*/
func (a *sodiumAES256GCM) ResetNonce(ctxt context.Context) error {
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
func (a *sodiumAES256GCM) Type() AEADTypeEnum {
	return AEADTypeAes256gcm
}

/*
Nonce return the current nonce value

	@returns the nonce
*/
func (a *sodiumAES256GCM) Nonce() SecureCSlice {
	return a.nonce
}

/*
ExpectedCipherLen compute the expected cipher text len given the plain text length

	@returns the expected cipher text length
*/
func (a *sodiumAES256GCM) ExpectedCipherLen(plainTextLen int64) int64 {
	return plainTextLen + C.crypto_aead_aes256gcm_ABYTES
}

/*
ExpectedPlainTextLen compute the expected plain text len given the cipher text length

	@returns the expected plain text length
*/
func (a *sodiumAES256GCM) ExpectedPlainTextLen(cipherLen int64) int64 {
	return cipherLen - C.crypto_aead_aes256gcm_ABYTES
}

/*
Seal encrypt plain text with associated additional data.

	@param ctxt context.Context - calling context
	@param msgIndex int64 - the message index within a stream
	@param plainText []byte - the plain text to encrypt
	@param additional []byte - the associated additional data
	@param cipherText []byte - the output buffer for the cipher text
*/
func (a *sodiumAES256GCM) Seal(
	ctxt context.Context, msgIndex int64, plainText []byte, additional []byte, cipherText []byte,
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
	resp := C.crypto_aead_aes256gcm_encrypt(
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
func (a *sodiumAES256GCM) Unseal(
	ctxt context.Context, msgIndex int64, cipherText []byte, additional []byte, plainText []byte,
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
	resp := C.crypto_aead_aes256gcm_decrypt(
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
