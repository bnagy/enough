package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"os"
)

var (
	cert = flag.String("cert", "", "Certificate file ( in PEM format ) containing the public key")
	sig  = flag.String("sig", "", "Signature file ( in raw DER ) to check")
	file = flag.String("file", "", "File being verified")
)

type ecdsaSig struct {
	R *big.Int
	S *big.Int
}

func main() {

	flag.Parse()
	if len(*sig) == 0 || len(*cert) == 0 || len(*file) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	raw, err := ioutil.ReadFile(*cert)
	if err != nil {
		log.Fatalf("failed to read cert from %s: %s", *cert, err)
	}
	certPEM, rest := pem.Decode(raw)
	if len(rest) != 0 || certPEM == nil {
		log.Fatalf("%s: invalid PEM data", *cert)
	}
	cert, err := x509.ParseCertificate(certPEM.Bytes)
	if err != nil {
		log.Fatalf("failed to parse certificate: %s\n", err)
	}

	raw, err = ioutil.ReadFile(*sig)
	if err != nil {
		log.Fatalf("failed to read sig from %s: %s", *sig, err)
	}
	sig := &ecdsaSig{}
	extra, err := asn1.Unmarshal(raw, sig)
	if err != nil || len(extra) != 0 {
		log.Fatalf("invalid signature data")
	}

	// Apparently there's no standard way to know what digest was used for an
	// ECDSA signature, it's literally just R and S blatted as an ASN.1
	// SEQUENCE. I've chosen to encode the public key we're verifying from in
	// a cert and use the SignatureAlgorithm x509 field from that, but who
	// knows if that's sensible.

	// we're doing it by hand this way so that we don't have to read all of
	// *file into a []byte. This is mostly copied from
	// /src/pkg/crypto/x509/x509.go?s=20823:20922#L606
	var hashType crypto.Hash

	switch cert.SignatureAlgorithm {
	case x509.ECDSAWithSHA1:
		hashType = crypto.SHA1
	case x509.ECDSAWithSHA256:
		hashType = crypto.SHA256
	case x509.ECDSAWithSHA384:
		hashType = crypto.SHA384
	case x509.ECDSAWithSHA512:
		hashType = crypto.SHA512
	default:
		log.Fatalf("unsupported hash algorithm")
	}
	if !hashType.Available() {
		log.Fatalf("unsupported hash algorithm")
	}
	h := hashType.New()

	fr, err := os.Open(*file)
	if err != nil {
		log.Fatalf("failed to open %s: %s\n", *file, err)
	}
	defer fr.Close()
	io.Copy(h, fr)

	digest := h.Sum(nil)

	if sig.R.Sign() <= 0 || sig.S.Sign() <= 0 {
		log.Fatalf("signature contained zero or negative values")
	}
	pub := cert.PublicKey.(*ecdsa.PublicKey)
	if !ecdsa.Verify(pub, digest, sig.R, sig.S) {
		log.Fatalf("[!!] verification failed")
	}

	fmt.Printf("Verify OK\n")

}
