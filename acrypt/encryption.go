package acrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"

	"golang.org/x/crypto/scrypt"
)

const Extension string = ".acrypt"

var Settings settings

type settings struct {
	N, R, P, SaltSize, KeySize int
}

func init() {
	Settings.N = 16384
	Settings.R = 8
	Settings.P = 1
	Settings.SaltSize = 32
	Settings.KeySize = 32
}

func Nonce(size int) ([]byte, error) {
	nonce := make([]byte, size)
	_, err := io.ReadFull(rand.Reader, nonce)
	return nonce, err
}

func GCMCipher(secret, salt []byte) (cipher.AEAD, error) {
	key, err := scrypt.Key(secret, salt, Settings.N, Settings.R, Settings.P, Settings.KeySize)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return cipher.NewGCM(block)
}
