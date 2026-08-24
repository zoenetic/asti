package main

import (
	"crypto/aes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
)

func weak() {
	_ = md5.New()  // crit:expect go.weak-crypto
	_ = sha1.New() // crit:expect go.weak-crypto
}

func strong(key []byte) {
	_ = sha256.New()       // crit:expect-not go.weak-crypto
	_, _ = aes.NewCipher(key) // crit:expect-not go.weak-crypto
}
