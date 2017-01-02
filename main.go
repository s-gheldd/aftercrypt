package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"

	"golang.org/x/crypto/ssh/terminal"
)

const (
	stdin int = iota
	stdout
)

var settings struct {
	secret  string
	decrypt bool
}

func init() {
	flag.StringVar(&settings.secret, "secret", "", "the secret used to en or decrypt")
	flag.StringVar(&settings.secret, "s", "", "the secret used to en or decrypt (shorthand)")
	flag.BoolVar(&settings.decrypt, "decrypt", false, "set for decryption mode")
	flag.BoolVar(&settings.decrypt, "d", false, "set for decryption mode (shorthand)")
	flag.Parse()
}

func main() {

	secret, err := getSecret()
	if err != nil {
		log.Fatal(err)
	}

	if settings.decrypt {
		decryptFiles(secret)
	} else {
		encryptFiles(secret)
	}

}

func decryptFiles(secret []byte) {
	args := flag.Args()
	done := make(chan struct{})
	errs := make(chan error)
	for _, relPath := range args {
		go decryptFile(secret, relPath, done, errs)
	}
	for range args {
		<-done
	}
}

func encryptFiles(secret []byte) {

	args := flag.Args()

	done := make(chan struct{})

	for _, relPath := range args {
		go encryptFile(secret, relPath, done)
	}

	for range args {
		<-done
	}
}

func logErrAndSignalDone(err error, done chan<- struct{}) {
	log.Println(err)
	done <- struct{}{}
}

func getSecret() ([]byte, error) {
	if settings.secret != "" {
		return []byte(settings.secret), nil
	}

	return getSecretFromTerminal()
}

func getSecretFromTerminal() ([]byte, error) {

	fmt.Print("Enter secret: ")
	secretOne, err := getOneFromTerminalSecret()
	if err != nil {
		return secretOne, err
	}

	fmt.Printf("\nRepeat secret:")
	secretTwo, err := getOneFromTerminalSecret()
	if err != nil {
		return secretTwo, err
	}
	fmt.Printf("\n")
	if bytes.Compare(secretOne, secretTwo) != 0 {
		return nil, fmt.Errorf("secrets entered do not match")
	}

	return secretOne, nil
}

func getOneFromTerminalSecret() ([]byte, error) {

	oldState, err := terminal.MakeRaw(stdin)
	if err != nil {
		return nil, err
	}
	defer terminal.Restore(stdin, oldState)

	return terminal.ReadPassword(stdin)
}
