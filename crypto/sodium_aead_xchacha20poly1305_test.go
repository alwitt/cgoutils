package crypto_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/alwitt/cgoutils/crypto"
	"github.com/apex/log"
	"github.com/stretchr/testify/assert"
)

func TestSodiumAEADXChaCha20Poly1305Basic(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtxt := context.Background()

	sodium, err := crypto.NewEngine(log.Fields{})
	assert.Nil(err)

	testAEADType := crypto.AEADTypeXChaCha20Poly1305

	uut, err := sodium.GetAEAD(utCtxt, testAEADType)
	assert.Nil(err)
	assert.Equal(testAEADType, uut.Type())

	testKey, err := sodium.GetRandomBuf(utCtxt, uut.ExpectedKeyLen())
	assert.Nil(err)
	testNonce, err := sodium.GetRandomBuf(utCtxt, uut.ExpectedNonceLen())
	assert.Nil(err)

	assert.Nil(uut.SetKey(testKey))
	assert.Nil(uut.SetNonce(testNonce))

	testMessage := make([]byte, 8192)
	{
		n, err := rand.Read(testMessage)
		assert.Nil(err)
		assert.Equal(8192, n)
	}

	// Encrypt the message
	encrypted := make([]byte, uut.ExpectedCipherLen(8192))
	assert.Nil(uut.Seal(utCtxt, 0, testMessage, nil, encrypted))

	// Decrypt the message
	decrypted := make([]byte, 8192)
	assert.Nil(uut.Unseal(utCtxt, 0, encrypted, nil, decrypted))

	// Verify the contents match
	assert.EqualValues(testMessage, decrypted)
}

func TestSodiumAEADXChaCha20Poly1305MultiMsg(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtxt := context.Background()

	sodium, err := crypto.NewEngine(log.Fields{})
	assert.Nil(err)

	testAEADType := crypto.AEADTypeXChaCha20Poly1305

	uut, err := sodium.GetAEAD(utCtxt, testAEADType)
	assert.Nil(err)
	assert.Equal(testAEADType, uut.Type())

	testKey, err := sodium.GetRandomBuf(utCtxt, uut.ExpectedKeyLen())
	assert.Nil(err)
	testNonce, err := sodium.GetRandomBuf(utCtxt, uut.ExpectedNonceLen())
	assert.Nil(err)

	assert.Nil(uut.SetKey(testKey))
	assert.Nil(uut.SetNonce(testNonce))

	testMsgs := [][]byte{}
	for itr := 0; itr < 3; itr++ {
		testMessage := make([]byte, 8192)
		n, err := rand.Read(testMessage)
		assert.Nil(err)
		assert.Equal(8192, n)
		testMsgs = append(testMsgs, testMessage)
	}

	// Encrypt the messages
	encMsgs := [][]byte{}
	for itr := 0; itr < 3; itr++ {
		encrypted := make([]byte, uut.ExpectedCipherLen(8192))
		assert.Nil(uut.Seal(utCtxt, 0, testMsgs[itr], nil, encrypted))
		encMsgs = append(encMsgs, encrypted)
	}

	// Decrypt the messages
	decMsgs := [][]byte{}
	for itr := 2; itr >= 0; itr-- {
		decrypted := make([]byte, 8192)
		assert.Nil(uut.Unseal(utCtxt, 0, encMsgs[itr], nil, decrypted))
		decMsgs = append(decMsgs, decrypted)
	}

	// Verify the messages matchs
	for itr := 0; itr < 3; itr++ {
		decrypted := decMsgs[2-itr]
		assert.EqualValues(testMsgs[itr], decrypted)
	}
}

func TestSodiumAEADXChaCha20Poly1305OutOfOrderMessage(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtxt := context.Background()

	sodium, err := crypto.NewEngine(log.Fields{})
	assert.Nil(err)

	testAEADType := crypto.AEADTypeXChaCha20Poly1305

	uut, err := sodium.GetAEAD(utCtxt, testAEADType)
	assert.Nil(err)
	assert.Equal(testAEADType, uut.Type())

	testKey, err := sodium.GetRandomBuf(utCtxt, uut.ExpectedKeyLen())
	assert.Nil(err)
	testNonce, err := sodium.GetRandomBuf(utCtxt, uut.ExpectedNonceLen())
	assert.Nil(err)

	assert.Nil(uut.SetKey(testKey))
	assert.Nil(uut.SetNonce(testNonce))

	testMessage := make([]byte, 8192)
	{
		n, err := rand.Read(testMessage)
		assert.Nil(err)
		assert.Equal(8192, n)
	}

	// Encrypt the message
	encrypted := make([]byte, uut.ExpectedCipherLen(8192))
	assert.Nil(uut.Seal(utCtxt, 0, testMessage, nil, encrypted))

	// Decrypt the message
	decrypted := make([]byte, 8192)
	assert.Nil(uut.Unseal(utCtxt, 0, encrypted, nil, decrypted))

	// Verify the contents match
	assert.EqualValues(testMessage, decrypted)

	// Decrypt the message
	assert.NotNil(uut.Unseal(utCtxt, 1, encrypted, nil, decrypted))
}

func TestSodiumAEADXChaCha20Poly1305CorruptedMessage(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtxt := context.Background()

	sodium, err := crypto.NewEngine(log.Fields{})
	assert.Nil(err)

	testAEADType := crypto.AEADTypeXChaCha20Poly1305

	uut, err := sodium.GetAEAD(utCtxt, testAEADType)
	assert.Nil(err)
	assert.Equal(testAEADType, uut.Type())

	testKey, err := sodium.GetRandomBuf(utCtxt, uut.ExpectedKeyLen())
	assert.Nil(err)
	testNonce, err := sodium.GetRandomBuf(utCtxt, uut.ExpectedNonceLen())
	assert.Nil(err)

	assert.Nil(uut.SetKey(testKey))
	assert.Nil(uut.SetNonce(testNonce))

	testMessage := make([]byte, 8192)
	{
		n, err := rand.Read(testMessage)
		assert.Nil(err)
		assert.Equal(8192, n)
	}

	// Encrypt the message
	encrypted := make([]byte, uut.ExpectedCipherLen(8192))
	assert.Nil(uut.Seal(utCtxt, 0, testMessage, nil, encrypted))

	// Decrypt the message
	decrypted := make([]byte, 8192)
	assert.Nil(uut.Unseal(utCtxt, 0, encrypted, nil, decrypted))

	// Verify the contents match
	assert.EqualValues(testMessage, decrypted)

	// Randomly modify the message
	modifyTarget, err := rand.Int(rand.Reader, big.NewInt(uut.ExpectedCipherLen(8192)))
	assert.Nil(err)
	encrypted[modifyTarget.Int64()] = encrypted[modifyTarget.Int64()] ^ 0xff

	// Decrypt the message
	assert.NotNil(uut.Unseal(utCtxt, 0, encrypted, nil, decrypted))
}

func TestSodiumAEADXChaCha20Poly1305AdditionalData(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtxt := context.Background()

	sodium, err := crypto.NewEngine(log.Fields{})
	assert.Nil(err)

	testAEADType := crypto.AEADTypeXChaCha20Poly1305

	uut, err := sodium.GetAEAD(utCtxt, testAEADType)
	assert.Nil(err)
	assert.Equal(testAEADType, uut.Type())

	testKey, err := sodium.GetRandomBuf(utCtxt, uut.ExpectedKeyLen())
	assert.Nil(err)
	testNonce, err := sodium.GetRandomBuf(utCtxt, uut.ExpectedNonceLen())
	assert.Nil(err)

	assert.Nil(uut.SetKey(testKey))
	assert.Nil(uut.SetNonce(testNonce))

	testMessage := make([]byte, 8192)
	{
		n, err := rand.Read(testMessage)
		assert.Nil(err)
		assert.Equal(8192, n)
	}
	testAdditional := make([]byte, 256)
	{
		n, err := rand.Read(testAdditional)
		assert.Nil(err)
		assert.Equal(256, n)
	}

	// Encrypt the message
	encrypted := make([]byte, uut.ExpectedCipherLen(8192))
	assert.Nil(uut.Seal(utCtxt, 0, testMessage, testAdditional, encrypted))

	// Decrypt the message
	decrypted := make([]byte, 8192)
	assert.Nil(uut.Unseal(utCtxt, 0, encrypted, testAdditional, decrypted))

	// Verify the contents match
	assert.EqualValues(testMessage, decrypted)

	// Decrypt the message
	assert.NotNil(uut.Unseal(utCtxt, 0, encrypted, nil, decrypted))
}

func TestSodiumAEADXChaCha20Poly1305ThroughPut(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.InfoLevel)

	if runningInCICD() {
		log.Debug("Skip throughput testing in CICD")
		return
	}

	utCtxt := context.Background()

	sodium, err := crypto.NewEngine(log.Fields{})
	assert.Nil(err)

	testAEADType := crypto.AEADTypeXChaCha20Poly1305

	uut, err := sodium.GetAEAD(utCtxt, testAEADType)
	assert.Nil(err)
	assert.Equal(testAEADType, uut.Type())

	testKey, err := sodium.GetRandomBuf(utCtxt, uut.ExpectedKeyLen())
	assert.Nil(err)
	testNonce, err := sodium.GetRandomBuf(utCtxt, uut.ExpectedNonceLen())
	assert.Nil(err)

	assert.Nil(uut.SetKey(testKey))
	assert.Nil(uut.SetNonce(testNonce))

	testFile, err := os.Open("../test/world192.txt")
	assert.Nil(err)
	defer func() {
		assert.Nil(testFile.Close())
	}()

	// Compute the hash of the file as we read
	hashKey, err := sodium.GetHasherKey(utCtxt)
	assert.Nil(err)
	testFileHasher, err := sodium.GetHasher(utCtxt, hashKey)
	assert.Nil(err)

	truncate := func(s []byte, to int) []byte {
		return s[:to]
	}

	// Read the file
	maxChunkSize := 8192 * 64
	testFileSize := 0
	fileChunks := [][]byte{}
	for itr := 0; ; itr++ {
		readBuffer := make([]byte, maxChunkSize)
		readN, err := testFile.Read(readBuffer)
		if err != nil {
			if err != io.EOF {
				assert.Nil(err)
			}
			break
		}
		if readN < maxChunkSize {
			readBuffer = truncate(readBuffer, readN)
		}
		assert.LessOrEqual(readN, maxChunkSize)
		assert.Nil(testFileHasher.Update(readBuffer))
		testFileSize += readN
		fileChunks = append(fileChunks, readBuffer)
	}
	assert.Nil(testFileHasher.Finalize())
	assert.Equal(2407154, testFileSize)
	testFileHash := testFileHasher.GetHash()
	log.Infof("Test file is %d, %s", testFileSize, base64.StdEncoding.EncodeToString(testFileHash))

	// Repeat the encryption and decryption repeatedly
	repeat := 1000

	// Repeatedly encrypt the file content
	cipherTexts := [][]byte{}
	encStartTime := time.Now().UTC()
	for itr := 0; itr < repeat; itr++ {
		if itr%(repeat/10) == 0 {
			log.WithField("itr", itr).Infof("Run encryption")
		}
		for idx, oneChunk := range fileChunks {
			cipherText := make([]byte, uut.ExpectedCipherLen(int64(len(oneChunk))))
			assert.Nil(uut.Seal(utCtxt, int64(idx), oneChunk, nil, cipherText))
			if itr == (repeat - 1) {
				cipherTexts = append(cipherTexts, cipherText)
			}
		}
	}
	encEndTime := time.Now().UTC()

	// Repeatedly decrypt the cipher text
	plainTexts := [][]byte{}
	decStartTime := time.Now().UTC()
	for itr := 0; itr < repeat; itr++ {
		if itr%(repeat/10) == 0 {
			log.WithField("itr", itr).Infof("Run decryption")
		}
		for idx, oneCipherText := range cipherTexts {
			plainText := make([]byte, uut.ExpectedPlainTextLen(int64(len(oneCipherText))))
			assert.Nil(uut.Unseal(utCtxt, int64(idx), oneCipherText, nil, plainText))
			if itr == (repeat - 1) {
				plainTexts = append(plainTexts, plainText)
			}
		}
	}
	decEndTime := time.Now().UTC()

	// Compute the decrypted plain texts hash
	decryptFileSize := 0
	decryptHasher, err := sodium.GetHasher(utCtxt, hashKey)
	assert.Nil(err)
	for _, oneText := range plainTexts {
		assert.Nil(decryptHasher.Update(oneText))
		decryptFileSize += len(oneText)
	}
	assert.Nil(decryptHasher.Finalize())
	assert.Equal(2407154, decryptFileSize)
	decryptHash := decryptHasher.GetHash()
	log.Infof(
		"Decrypted is %d, %s", decryptFileSize, base64.StdEncoding.EncodeToString(decryptHash),
	)

	assert.Equal(testFileSize, decryptFileSize)
	assert.EqualValues(testFileHash, decryptHash)

	{
		timeLapse := encEndTime.Sub(encStartTime)
		encryptionRate := (float64(testFileSize) * float64(repeat)) / timeLapse.Seconds()
		log.
			WithField("rate (MB/s)", encryptionRate/(1024*1024*8)).
			WithField("chunk (B)", maxChunkSize).
			Info("Encryption rate")
	}

	{
		timeLapse := decEndTime.Sub(decStartTime)
		decryptionRate := (float64(testFileSize) * float64(repeat)) / timeLapse.Seconds()
		log.
			WithField("rate (MB/s)", decryptionRate/(1024*1024*8)).
			WithField("chunk (B)", maxChunkSize).
			Info("Decryption rate")
	}
}
