package cgoutils

// #cgo CFLAGS: -O3 -Wall
// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"

import "fmt"

// sodiumCrypto `libsodium` wrapper client which implements Crypto
type sodiumCrypto struct{}

// init initialize `libsodium` for use
func (c *sodiumCrypto) init() error {
	if int(C.sodium_init()) != 0 {
		return fmt.Errorf("failed to initialize 'libsodium'")
	}
	return nil
}
