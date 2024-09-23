package crypto

// #include <stdlib.h>
// #include <sodium.h>
import "C"
import (
	"context"
	"fmt"
	"unsafe"

	"github.com/apex/log"
)

const (
	// SodiumPBKDFOutputMin minimum PBKDF target key length
	SodiumPBKDFOutputMin = C.crypto_pwhash_BYTES_MIN
	// SodiumPBKDFOutputMax maximum PBKDF target key length
	SodiumPBKDFOutputMax = C.crypto_pwhash_BYTES_MAX

	// SodiumPBKDFPasswdMin minimum PBKDF input password length
	SodiumPBKDFPasswdMin = C.crypto_pwhash_PASSWD_MIN

	// SodiumPBKDFOpsLimitMin minimum PBKDF OPS limit
	SodiumPBKDFOpsLimitMin = C.crypto_pwhash_OPSLIMIT_MIN
	// SodiumPBKDFOpsLimitFast fast PBKDF OPS limit
	SodiumPBKDFOpsLimitFast = C.crypto_pwhash_OPSLIMIT_INTERACTIVE
	// SodiumPBKDFOpsLimitMed medium PBKDF OPS limit
	SodiumPBKDFOpsLimitMed = C.crypto_pwhash_OPSLIMIT_MODERATE
	// SodiumPBKDFOpsLimitSlow slow PBKDF OPS limit
	SodiumPBKDFOpsLimitSlow = C.crypto_pwhash_OPSLIMIT_SENSITIVE
	// SodiumPBKDFOpsLimitMax maximum PBKDF OPS limit
	SodiumPBKDFOpsLimitMax = C.crypto_pwhash_OPSLIMIT_MAX

	// SodiumPBKDFMemLimitMin minimum PBKDF MEM limit
	SodiumPBKDFMemLimitMin = C.crypto_pwhash_MEMLIMIT_MIN
	// SodiumPBKDFMemLimitFast fast PBKDF MEM limit
	SodiumPBKDFMemLimitFast = C.crypto_pwhash_MEMLIMIT_INTERACTIVE
	// SodiumPBKDFMemLimitMed medium PBKDF MEM limit
	SodiumPBKDFMemLimitMed = C.crypto_pwhash_MEMLIMIT_MODERATE
	// SodiumPBKDFMemLimitSlow slow PBKDF MEM limit
	SodiumPBKDFMemLimitSlow = C.crypto_pwhash_MEMLIMIT_SENSITIVE
	// SodiumPBKDFMemLimitMax maximum PBKDF MEM limit
	SodiumPBKDFMemLimitMax = C.crypto_pwhash_MEMLIMIT_MAX
)

/*
GetPBKDFSalt get a salt for use with PBKDF

	@param ctxt context.Context - calling context
	@returns new salt
*/
func (c *sodiumCrypto) GetPBKDFSalt(ctxt context.Context) (SecureCSlice, error) {
	return c.GetRandomBuf(ctxt, C.crypto_pwhash_SALTBYTES)
}

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
func (c *sodiumCrypto) PBKDF(
	ctxt context.Context,
	passwd []byte,
	salt SecureCSlice,
	opsLimit uint64,
	memLimit uint64,
	outLength int,
) (SecureCSlice, error) {
	logTags := c.GetLogTagsForContext(ctxt)

	// Verify the inputs
	if len(passwd) < C.crypto_pwhash_PASSWD_MIN || len(passwd) > C.crypto_pwhash_PASSWD_MAX {
		err := fmt.Errorf("password failed length constraint")
		log.WithError(err).WithFields(logTags).Error("Key derivation input failure")
		return nil, err
	}
	if saltLen, err := salt.GetLen(); err != nil {
		log.WithError(err).WithFields(logTags).Error("Unable to read salt length")
		return nil, err
	} else if saltLen != C.crypto_pwhash_SALTBYTES {
		err := fmt.Errorf("salt failed length constraint")
		log.WithError(err).WithFields(logTags).Error("Key derivation input failure")
		return nil, err
	}
	if opsLimit < C.crypto_pwhash_OPSLIMIT_MIN || opsLimit > C.crypto_pwhash_OPSLIMIT_MAX {
		err := fmt.Errorf("computation complexity limit outside of supported range")
		log.WithError(err).WithFields(logTags).Error("Key derivation input failure")
		return nil, err
	}
	if memLimit < C.crypto_pwhash_MEMLIMIT_MIN || memLimit > C.crypto_pwhash_MEMLIMIT_MAX {
		err := fmt.Errorf("memory complexity limit outside of supported range")
		log.WithError(err).WithFields(logTags).Error("Key derivation input failure")
		return nil, err
	}
	if outLength < C.crypto_pwhash_BYTES_MIN || outLength > C.crypto_pwhash_BYTES_MAX {
		err := fmt.Errorf("target key length outside of supported range")
		log.WithError(err).WithFields(logTags).Error("Key derivation input failure")
		return nil, err
	}

	// Generate output buffer
	output, err := c.AllocateCryptoCSlice(outLength)
	if err != nil {
		log.WithError(err).WithFields(logTags).Error("Failed to allocate output buffer")
		return nil, err
	}

	outputPtr, err := output.GetCArray()
	if err != nil {
		log.WithError(err).WithFields(logTags).Error("Unable to get output buffer pointer")
		return nil, err
	}

	saltPtr, err := salt.GetCArray()
	if err != nil {
		log.WithError(err).WithFields(logTags).Error("Unable to get salt pointer")
		return nil, err
	}

	resp := int(C.crypto_pwhash(
		(*C.uchar)(outputPtr),
		C.ulonglong(outLength),
		(*C.char)(unsafe.Pointer(&passwd[0])),
		C.ulonglong(len(passwd)),
		(*C.uchar)(saltPtr),
		C.ulonglong(opsLimit),
		C.size_t(memLimit),
		C.crypto_pwhash_ALG_ARGON2ID13,
	))
	if resp != 0 {
		err := fmt.Errorf("key derivation failed with %d", resp)
		return nil, err
	}

	return output, nil
}
