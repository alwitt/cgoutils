package common

import "github.com/alwitt/goutils"

// CError C function call error
type CError struct{ goutils.BaseError }

// NewCError builds a CError, optionally capturing the call stack.
func NewCError(message string, core error, getCallStack bool) CError {
	base := goutils.BaseError{Name: "CError", Message: message, Core: core}
	if getCallStack {
		base.Stack = goutils.GetCallStack(1)
	}
	return CError{BaseError: base}
}

// SodiumError libsodium function call error
type SodiumError struct{ goutils.BaseError }

// NewSodiumError builds a SodiumError, optionally capturing the call stack.
func NewSodiumError(message string, core error, getCallStack bool) SodiumError {
	base := goutils.BaseError{Name: "SodiumError", Message: message, Core: core}
	if getCallStack {
		base.Stack = goutils.GetCallStack(1)
	}
	return SodiumError{BaseError: base}
}

// CryptoError Go standard crypto library call error
type CryptoError struct{ goutils.BaseError }

// NewCryptoError builds a CryptoError, optionally capturing the call stack.
func NewCryptoError(message string, core error, getCallStack bool) CryptoError {
	base := goutils.BaseError{Name: "CryptoError", Message: message, Core: core}
	if getCallStack {
		base.Stack = goutils.GetCallStack(1)
	}
	return CryptoError{BaseError: base}
}
