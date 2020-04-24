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
	testKey256 []byte
)

func TestCreateKey128Bit(t *testing.T) {
	var err error
	testKey128, err = CreateKey(KeySize128Bit)
	if nil != err {
		t.Fatalf("%v", err)
	}
	if len(testKey128) != 128/8 {
		t.Fatalf("CreateKey(%d) = %d; want %d", KeySize256Bit, len(testKey128), KeySize256Bit)
	}
}

func TestCreateKey256Bit(t *testing.T) {
	var err error
	testKey256, err = CreateKey(KeySize256Bit)
	if nil != err {
		t.Fatalf("%v", err)
	}
	if len(testKey256) != 256/8 {
		t.Fatalf("CreateKey(%d) = %d; want %d", KeySize256Bit, len(testKey256), KeySize256Bit)
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
