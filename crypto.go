package cgoutils

// Crypto wrapper object for performing
type Crypto interface{}

/*
NewSodiumCrypto define a `libsodium` backed Crypto object.

	@returns new Crypto object
*/
func NewSodiumCrypto() (Crypto, error) {
	instance := &sodiumCrypto{}
	return instance, instance.init()
}
