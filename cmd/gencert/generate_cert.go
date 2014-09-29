package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/bnagy/enough"
)

var (
	service = flag.String("service", "", "Service name eg 'WidgetCluser' (required)")
	clients = flag.Int("clients", 1, "Number of client cert / keys to generate")
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
	log.Printf("written %s\n", certName)

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
	log.Printf("written %s\n", keyName)
}

func main() {

	flag.Parse()
	if len(*service) == 0 {
		flag.Usage()
		log.Fatal("\nService name required!")
	}
	if len(*service) > 140 {
		flag.Usage()
		log.Fatal("\nOh, grow up.")
	}
	ca, err := enough.NewCA(*service)
	output(&ca.Raw, "ca")
	server, err := ca.CreateServerCert()
	if err != nil {
		log.Fatalf("unable to create server cert: %s", err)
	}
	output(server, "server")
	for i := 0; i < *clients; i++ {
		c, err := ca.CreateClientCert(i)
		if err != nil {
			log.Fatalf("unable to create cilent cert %d: %s", i, err)
		}
		output(c, fmt.Sprintf("client%d", i))
	}

}
