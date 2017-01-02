package main

import (
	"log"
	"os"
	"strings"

	"github.com/s-gheldd/aftercrypt/acrypt"
)

func decryptFile(secret []byte, relPath string, done chan<- struct{}, errs chan<- error) {

	absPath, err := sanityCheckFile(relPath)
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

	aFile, err := acrypt.Deserialize(input)
	if err != nil {
		logErrAndSignalDone(err, done)
		return
	}

	cipher, err := acrypt.GCMCipher(secret, aFile.Key.Salt)
	if err != nil {
		logErrAndSignalDone(err, done)
		return
	}

	payload := aFile.Payload
	payload, err = cipher.Open(payload[:0], aFile.Nonce, payload, nil)
	if err != nil {
		logErrAndSignalDone(err, done)
		return
	}

	output, err := os.Create(outPutFileName(absPath))
	if err != nil {
		logErrAndSignalDone(err, done)
		return
	}
	defer output.Close()

	_, err = output.Write(payload)
	if err != nil {
		logErrAndSignalDone(err, done)
		return
	}

	done <- struct{}{}
}

func outPutFileName(absPath string) string {
	if strings.HasSuffix(absPath, acrypt.Extension) {
		return absPath[:len(absPath)-len(acrypt.Extension)]
	}
	return absPath + ".dec"
}

func errorHandler(errs <-chan error) {

	for {
		log.Println(<-errs)
	}

}
