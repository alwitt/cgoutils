package crypto

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
