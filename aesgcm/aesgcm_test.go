package aesgcm

import (
	"bytes"
	"testing"
)

const (
	rawMessage = "This is a very secret message."
)

var (
	testKey128 []byte
	testKey192 []byte
	testKey256 []byte
)

func TestCreateKey128Bit(t *testing.T) {
	const keySize = 128
	var err error
	testKey128, err = CreateKey(keySize)
	if nil != err {
		t.Fatalf("%v", err)
	}
	if len(testKey128) != keySize/8 {
		t.Fatalf("CreateKey(%d) = %d; want %d", keySize, len(testKey128), keySize)
	}
}

func TestCreateKey192Bit(t *testing.T) {
	const keySize = 192
	var err error
	testKey192, err = CreateKey(keySize)
	if nil != err {
		t.Fatalf("%v", err)
	}
	if len(testKey192) != keySize/8 {
		t.Fatalf("CreateKey(%d) = %d; want %d", 192, len(testKey192), keySize)
	}
}

func TestCreateKey256Bit(t *testing.T) {
	const keySize = 256
	var err error
	testKey256, err = CreateKey(keySize)
	if nil != err {
		t.Fatalf("%v", err)
	}
	if len(testKey256) != keySize/8 {
		t.Fatalf("CreateKey(%d) = %d; want %d", keySize, len(testKey256), keySize)
	}
}

func TestEncrypt128(t *testing.T) {
	got, err := Encrypt(testKey128, []byte(rawMessage))
	if nil != err {
		t.Error(err)
		t.FailNow()
	}
	decrypt, err := Decrypt(testKey128, got)
	if !bytes.Equal([]byte(rawMessage), decrypt) {
		t.Fatalf("Encrypt(%d, %s) = %s; want %s", testKey128, rawMessage, decrypt, rawMessage)
	}
}

func TestDecrypt128(t *testing.T) {
	/*
		decrypt, err := Decrypt()
		if nil != err {
			t.Error(err)
		}
	*/
}
