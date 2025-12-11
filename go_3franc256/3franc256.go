package main

import (
	"bytes"
	"compress/zlib"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha3"
	"crypto/subtle"
	"errors"
	"hash"
	"io"

	"golang.org/x/crypto/argon2"
)

func Encryption(userText []byte, key []byte) ([]byte, error) {
	salt, err := GetRandomByte()
	if err != nil {
		return nil, err
	}
	var secretKey []byte = generateSecretKey(key, salt)

	compressedText, err := compressData(userText)
	if err != nil {
		return nil, err
	}
	c := make(chan []byte)
	go cipher(c)
	c <- compressedText
	c <- secretKey
	var encryptedText []byte = <-c

	var mac []byte = generateMac(secretKey, encryptedText)

	var buffer bytes.Buffer
	buffer.Write(salt)
	buffer.Write(encryptedText)
	buffer.Write(mac)
	var combinedData []byte = buffer.Bytes()

	return combinedData, nil
}

func Decryption(userText []byte, key []byte) ([]byte, error) {
	if len(userText) < 64 {
		return nil, errors.New("incorrect text")
	}
	var salt []byte = userText[:32]
	var mac []byte = userText[len(userText)-32:]
	var encryptedText []byte = userText[32 : len(userText)-32]

	var secretKey []byte = generateSecretKey(key, salt)

	var checkMac []byte = generateMac(secretKey, encryptedText)

	if subtle.ConstantTimeCompare(checkMac, mac) != 1 {
		return nil, errors.New("decryption failed")
	}

	c := make(chan []byte)
	go cipher(c)
	c <- encryptedText
	c <- secretKey
	result, err := decompressData(<-c) // c : decrypted data
	if err != nil {
		return nil, err
	}

	return result, nil
}

func GetRandomByte() ([]byte, error) {
	var b []byte = make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func cipher(c chan []byte) {
	var text []byte = <-c
	var key []byte = <-c
	var derivedKey []byte = generateShake(key, len(text))
	var result []byte = make([]byte, len(text))
	for i := range len(text) {
		result[i] = text[i] ^ derivedKey[i]
	}
	c <- result
}

func generateSecretKey(key []byte, salt []byte) []byte {
	return argon2.IDKey(key, salt, 2, 64*1024, 2, 32)
}

func generateMac(key []byte, text []byte) []byte {
	hashSha3 := sha3.New512()
	hashSha3.Write(key)
	var hashKey []byte = hashSha3.Sum(nil)

	h := hmac.New(func() hash.Hash { return sha3.New512() }, hashKey)
	h.Write(text)
	hmacValue := h.Sum(nil)
	return generateShake(hmacValue, 32)
}

func compressData(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	writer := zlib.NewWriter(&buf)

	_, err := writer.Write(data)
	if err != nil {
		return nil, err
	}

	err = writer.Close()
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func decompressData(compressed []byte) ([]byte, error) {
	reader, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	var buf bytes.Buffer
	_, err = io.Copy(&buf, reader)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func generateShake(data []byte, length int) []byte {
	shake := sha3.NewSHAKE256()

	shake.Write(data)

	hashValue := make([]byte, length)
	shake.Read(hashValue)
	return hashValue
}
