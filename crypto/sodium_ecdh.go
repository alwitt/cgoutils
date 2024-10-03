package crypto

// #include <stdlib.h>
// #include <sodium.h>
import "C"
import (
	"context"
	"fmt"

	"github.com/apex/log"
)

// ECDHKeyPair a ECDH key pair
type ECDHKeyPair struct {
	// Private the private portion of the DC key pair
	Private SecureCSlice
	// Public the public portion of the DC key pair
	Public SecureCSlice
}

// ECDHSessionKeys set of ECDH session keys
type ECDHSessionKeys struct {
	// RX key associated with data received from the other side
	RX SecureCSlice
	// TX key associated with data sent to the other side
	TX SecureCSlice
}

/*
NewECDHKeyPair generate a new ECDH key pair

	@param ctxt context.Context - calling context
	@returns the generated key pair
*/
func (c *engineImpl) NewECDHKeyPair(ctxt context.Context) (ECDHKeyPair, error) {
	logTags := c.GetLogTagsForContext(ctxt)

	// Prepare two buffer to hold the private and public keys
	privateSlice, err := c.AllocateSecureCSlice(C.crypto_kx_SECRETKEYBYTES)
	if err != nil {
		log.WithError(err).WithFields(logTags).Error("Failed to allocate ECDH private key buffer")
		return ECDHKeyPair{}, err
	}
	publicSlice, err := c.AllocateSecureCSlice(C.crypto_kx_PUBLICKEYBYTES)
	if err != nil {
		log.WithError(err).WithFields(logTags).Error("Failed to allocate ECDH public key buffer")
		return ECDHKeyPair{}, err
	}

	privatePtr, err := privateSlice.GetCArray()
	if err != nil {
		log.WithError(err).WithFields(logTags).Error("Unable to get ECDH private key buffer pointer")
		return ECDHKeyPair{}, err
	}
	publicPtr, err := publicSlice.GetCArray()
	if err != nil {
		log.WithError(err).WithFields(logTags).Error("Unable to get ECDH public key buffer pointer")
		return ECDHKeyPair{}, err
	}

	resp := int(C.crypto_kx_keypair((*C.uchar)(publicPtr), (*C.uchar)(privatePtr)))
	if resp != 0 {
		err := fmt.Errorf("ecdh key pair derivation failed with %d", resp)
		return ECDHKeyPair{}, err
	}

	return ECDHKeyPair{Private: privateSlice, Public: publicSlice}, nil
}

/*
ComputeClientECDHSessionKeys run client side ECDH and generate client side ECDH session keys

	@param ctxt context.Context - calling context
	@param clientKeys ECDHKeyPair - client ECDH key pair
	@param serverPublic SecureCSlice - server public key
	@returns client side ECDH session keys
*/
func (c *engineImpl) ComputeClientECDHSessionKeys(
	ctxt context.Context, clientKeys ECDHKeyPair, serverPublic SecureCSlice,
) (ECDHSessionKeys, error) {
	logTags := c.GetLogTagsForContext(ctxt)

	// Prepare two buffer to hold the RX and TX session keys
	rxSlice, err := c.AllocateSecureCSlice(C.crypto_kx_SESSIONKEYBYTES)
	if err != nil {
		log.WithError(err).WithFields(logTags).Error("Failed to allocate ECDH RX session key buffer")
		return ECDHSessionKeys{}, err
	}
	txSlice, err := c.AllocateSecureCSlice(C.crypto_kx_SESSIONKEYBYTES)
	if err != nil {
		log.WithError(err).WithFields(logTags).Error("Failed to allocate ECDH TX session key buffer")
		return ECDHSessionKeys{}, err
	}

	rxPtr, err := rxSlice.GetCArray()
	if err != nil {
		log.
			WithError(err).
			WithFields(logTags).
			Error("Unable to get ECDH RX session key buffer pointer")
		return ECDHSessionKeys{}, err
	}
	txPtr, err := txSlice.GetCArray()
	if err != nil {
		log.
			WithError(err).
			WithFields(logTags).
			Error("Unable to get ECDH TX session key buffer pointer")
		return ECDHSessionKeys{}, err
	}

	clientPrivatePtr, err := clientKeys.Private.GetCArray()
	if err != nil {
		log.
			WithError(err).
			WithFields(logTags).
			Error("Unable to get client ECDH private key buffer pointer")
		return ECDHSessionKeys{}, err
	}
	clientPublicPtr, err := clientKeys.Public.GetCArray()
	if err != nil {
		log.
			WithError(err).
			WithFields(logTags).
			Error("Unable to get client ECDH public key buffer pointer")
		return ECDHSessionKeys{}, err
	}
	serverPublicPtr, err := serverPublic.GetCArray()
	if err != nil {
		log.
			WithError(err).
			WithFields(logTags).
			Error("Unable to get server ECDH public key buffer pointer")
		return ECDHSessionKeys{}, err
	}

	resp := int(C.crypto_kx_client_session_keys(
		(*C.uchar)(rxPtr),
		(*C.uchar)(txPtr),
		(*C.uchar)(clientPublicPtr),
		(*C.uchar)(clientPrivatePtr),
		(*C.uchar)(serverPublicPtr),
	))
	if resp != 0 {
		err := fmt.Errorf("client ECDH session keys derivation failed with %d", resp)
		return ECDHSessionKeys{}, err
	}

	return ECDHSessionKeys{RX: rxSlice, TX: txSlice}, nil
}

/*
ComputeServerECDHSessionKeys run server side ECDH and generate server side ECDH session keys

	@param ctxt context.Context - calling context
	@param serverKeys ECDHKeyPair - server ECDH key pair
	@param clientPublic SecureCSlice - client public key
	@returns server side ECDH session keys
*/
func (c *engineImpl) ComputeServerECDHSessionKeys(
	ctxt context.Context, serverKeys ECDHKeyPair, clientPublic SecureCSlice,
) (ECDHSessionKeys, error) {
	logTags := c.GetLogTagsForContext(ctxt)

	// Prepare two buffer to hold the RX and TX session keys
	rxSlice, err := c.AllocateSecureCSlice(C.crypto_kx_SESSIONKEYBYTES)
	if err != nil {
		log.WithError(err).WithFields(logTags).Error("Failed to allocate ECDH RX session key buffer")
		return ECDHSessionKeys{}, err
	}
	txSlice, err := c.AllocateSecureCSlice(C.crypto_kx_SESSIONKEYBYTES)
	if err != nil {
		log.WithError(err).WithFields(logTags).Error("Failed to allocate ECDH TX session key buffer")
		return ECDHSessionKeys{}, err
	}

	rxPtr, err := rxSlice.GetCArray()
	if err != nil {
		log.
			WithError(err).
			WithFields(logTags).
			Error("Unable to get ECDH RX session key buffer pointer")
		return ECDHSessionKeys{}, err
	}
	txPtr, err := txSlice.GetCArray()
	if err != nil {
		log.
			WithError(err).
			WithFields(logTags).
			Error("Unable to get ECDH TX session key buffer pointer")
		return ECDHSessionKeys{}, err
	}

	serverPrivatePtr, err := serverKeys.Private.GetCArray()
	if err != nil {
		log.
			WithError(err).
			WithFields(logTags).
			Error("Unable to get server ECDH private key buffer pointer")
		return ECDHSessionKeys{}, err
	}
	serverPublicPtr, err := serverKeys.Public.GetCArray()
	if err != nil {
		log.
			WithError(err).
			WithFields(logTags).
			Error("Unable to get server ECDH public key buffer pointer")
		return ECDHSessionKeys{}, err
	}
	clientPublicPtr, err := clientPublic.GetCArray()
	if err != nil {
		log.
			WithError(err).
			WithFields(logTags).
			Error("Unable to get client ECDH public key buffer pointer")
		return ECDHSessionKeys{}, err
	}

	resp := int(C.crypto_kx_server_session_keys(
		(*C.uchar)(rxPtr),
		(*C.uchar)(txPtr),
		(*C.uchar)(serverPublicPtr),
		(*C.uchar)(serverPrivatePtr),
		(*C.uchar)(clientPublicPtr),
	))
	if resp != 0 {
		err := fmt.Errorf("server ECDH session keys derivation failed with %d", resp)
		return ECDHSessionKeys{}, err
	}

	return ECDHSessionKeys{RX: rxSlice, TX: txSlice}, nil
}
