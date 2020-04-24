// Package aesgcm provides a simple API to symmetric key encrypt/decrypt with
// AES Galois/Counter Mode (GCM),
package aesgcm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

const (
	errorPrefix           = "gocrypto: aesgcm: "
	KeySize128Bit KeySize = 16
	KeySize256Bit KeySize = 32
)

var (
	errorMsgNonce     = errors.New(errorPrefix + "creating nonce failed")
	errorMsgEncrypt   = errors.New(errorPrefix + "encryption failed")
	errorMsgDecrypt   = errors.New(errorPrefix + "decryption failed")
	errorMsgCreateKey = errors.New(errorPrefix + "key creation failed")
)

// Size of key in bytes
type KeySize int

// mergeError merges to errors.
//
// Useful when adding external error to the context error.
func mergeError(first error, second error) error {
	firstString := first.Error()
	secondString := second.Error()
	return errors.New(fmt.Sprintf("%s: %s", firstString, secondString))
}

func createNonce(size int) ([]byte, error) {
	nonce := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, mergeError(errorMsgNonce, err)
	}
	return nonce, nil
}

// CreateKey returns a valid key (secret) of a certain size,
// to be used when encrypting/decrypting AES.
//
// This function should be used by applications importing this lib.
// E.g by servers where the key must be known to the clients where encryption
// is involved.
func CreateKey(size KeySize) ([]byte, error) {
	key := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, key); nil != err {
		return nil, mergeError(errorMsgCreateKey, err)
	}
	return key, nil
}

// Encrypt returns the encrypted message where the provided key has
// been used during encryption.
func Encrypt(key, message []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if nil != err {
		return nil, mergeError(errorMsgEncrypt, err)
	}

	gcm, err := cipher.NewGCM(c)
	if nil != err {
		return nil, mergeError(errorMsgEncrypt, err)
	}

	nonce, err := createNonce(gcm.NonceSize())
	if nil != err {
		return nil, mergeError(errorMsgEncrypt, err)
	}

	seal := gcm.Seal(nonce, nonce, message, nil)
	if len(seal) == 0 {
		return nil, errorMsgEncrypt
	}
	return seal, nil
}

// Decrypt returns the decrypted message where the provided key
// must be the same key used when encrypting the message.
func Decrypt(key, message []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if nil != err {
		return nil, mergeError(errorMsgDecrypt, err)
	}

	gcm, err := cipher.NewGCM(c)
	if nil != err {
		return nil, mergeError(errorMsgDecrypt, err)
	}

	if len(message) <= gcm.NonceSize() {
		return nil, errorMsgDecrypt
	}

	nonce := make([]byte, gcm.NonceSize())
	copy(nonce, message)

	open, err := gcm.Open(nil, nonce, message[gcm.NonceSize():], nil)
	if nil != err {
		return nil, mergeError(errorMsgDecrypt, err)
	}
	return open, errorMsgDecrypt
}
