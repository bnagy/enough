package main

import (
	"errors"
	"flag"
	"fmt"
	"github.com/bnagy/enough"
	"io/ioutil"
	"log"
	"os"
)

var (
	name         = flag.String("name", "", "A short, shared service name eg 'WidgetCluser' (required)")
	clients      = flag.Int("clients", 1, "Number of client cert / keys to generate")
	clientOffset = flag.Int("client-offset", 0, "Index to start minting new client certs from")
	caCertPath   = flag.String("ca-cert", "", "Path to the CA cert pem file")
	caKeyPath    = flag.String("ca-key", "", "Path to the CA private key pem file")
)

func output(c *enough.RawCert, stub string) {

	certName := stub + "_cert.pem"
	certOut, err := os.Create(certName) // not sensitive, use create defaults
	if err != nil {
		log.Fatalf("failed to open %s for writing: %s", certName, err)
	}

	pem, err := c.MarshalCertificate()
	if err != nil {
		log.Fatalf("failed to marshal %s: %s", certName, err)
	}

	_, err = certOut.Write(pem)
	if err != nil {
		log.Fatalf("failed to write %s: %s", certName, err)
	}
	certOut.Close()

	keyName := stub + "_key.pem"
	keyOut, err := os.OpenFile(keyName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("failed to open %s for writing: %s", keyName, err)
	}

	pem, err = c.MarshalPrivateKey()
	if err != nil {
		log.Fatalf("failed to marshal %s: %s", certName, err)
	}

	_, err = keyOut.Write(pem)
	if err != nil {
		log.Fatalf("failed to write %s: %s", keyName, err)
	}

	keyOut.Close()
	log.Printf("wrote %s, %s\n", certName, keyName)
}

/**
 * Helper method which ensures all values are set and returns true if they are.
 */
func present(values ...string) bool {
	for _, v := range values {
		if len(v) == 0 {
			return false
		}
	}
	return true
}

/**
 * Helper method to ensure the proper combination of flags was provided and attempt to create a CA
 * either by requesting a new one from enough or using provided PEM data to instantiate one.
 */
func validateFlagsAndReturnCA() (ca *enough.CA, e error) {

	var err error

	if (!present(*name) && !present(*caCertPath) && !present(*caKeyPath)) || present(*name, *caCertPath, *caKeyPath) {
		flag.Usage()
		e = errors.New("name OR ca-cert and ca-key flag required!")
	} else if present(*name) && len(*name) > 140 {
		flag.Usage()
		e = errors.New("Provided name is too long! Must be less than 140 characters.")
	} else if present(*caCertPath, *caKeyPath) {
		// Attempt to read cert and key files and create a CA struct from them
		pemCert, err := ioutil.ReadFile(*caCertPath)
		if err != nil {
			e = fmt.Errorf("Failed to read ca-cert: %s", err)
			return
		}
		pemKey, err := ioutil.ReadFile(*caKeyPath)
		if err != nil {
			e = fmt.Errorf("Failed to read ca-key: %s", err)
			return
		}
		ca, e = enough.NewCAFromCertAndKey(pemCert, pemKey)

	} else if present(*name) && !present(*caCertPath) && !present(*caKeyPath) {
		// Create a new CA struct based on a service name
		ca, err = enough.NewCA(*name)
		if err != nil {
			e = fmt.Errorf("Failed to create CA cert: %s", err)
			return
		}
		output(&ca.Raw, "ca")

		server, err := ca.CreateServerCert()
		if err != nil {
			e = fmt.Errorf("Failed to create cert: %s", err)
			return
		}
		output(server, "server")

	} else {
		flag.Usage()
		e = errors.New("name OR ca-cert and ca-key flag required!")
	}
	return
}

func main() {
	var ca *enough.CA
	flag.Parse()

	ca, err := validateFlagsAndReturnCA()
	if err != nil {
		log.Fatalf("\nBad configuration flags: %s", err)
		return
	}

	for i := *clientOffset; i < (*clientOffset + *clients); i++ {
		c, err := ca.CreateClientCert(i)
		if err != nil {
			log.Fatalf("unable to create cilent cert %d: %s", i, err)
		}
		output(c, fmt.Sprintf("client%d", i))
	}

}
