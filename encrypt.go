package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/s-gheldd/aftercrypt/acrypt"
)

func sanityCheckFile(relPath string) (string, error) {
	absPath, err := filepath.Abs(relPath)
	if err != nil {
		return "", err
	}

	info, err := os.Lstat(absPath)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("file %s is not regular file %v", relPath, info.Mode())
	}
	return absPath, nil
}

func encryptFile(secret []byte, relPath string, done chan<- struct{}) {

	absPath, err := sanityCheckFile(relPath)
	if err != nil {
		logErrAndSignalDone(err, done)
		return
	}

	salt, err := acrypt.Nonce(acrypt.Settings.SaltSize)
	if err != nil {
		logErrAndSignalDone(err, done)
		return
	}
	cipher, err := acrypt.GCMCipher(secret, salt)
	if err != nil {
		logErrAndSignalDone(err, done)
		return
	}

	input, err := os.Open(absPath)
	if err != nil {
		logErrAndSignalDone(err, done)
		return
	}
	defer input.Close()

	output, err := os.Create(absPath + acrypt.Extension)
	if err != nil {
		logErrAndSignalDone(err, done)
		return
	}
	defer output.Close()

	nonce, err := acrypt.Nonce(cipher.NonceSize())
	if err != nil {
		logErrAndSignalDone(err, done)
		return
	}

	bytes, err := ioutil.ReadAll(input)
	if err != nil {
		logErrAndSignalDone(err, done)
		return
	}

	bytes = cipher.Seal(bytes[:0], nonce, bytes, nil)

	fileContent := &acrypt.File{Nonce: nonce, Key: acrypt.NewKey(salt), Payload: bytes}
	err = fileContent.Serialize(output)
	if err != nil {
		logErrAndSignalDone(err, done)
		return
	}
	done <- struct{}{}
}
