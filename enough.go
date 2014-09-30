package enough

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

type RawCert struct {
	PrivateKey  *ecdsa.PrivateKey
	Certificate x509.Certificate
}

func (c *RawCert) MarshalPrivateKey() ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(c.PrivateKey)
	if err != nil {
		return nil, err
	}
	keyBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	return keyBytes, nil
}

func (c *RawCert) MarshalCertificate() ([]byte, error) {
	// this can't error, I just want to have matching API signatures
	certBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Certificate.Raw})
	return certBytes, nil
}

type CA struct {
	Raw     RawCert
	Service string
}

func NewCA(service string) (ca *CA, e error) {

	name := pkix.Name{
		Organization: []string{"Just Enough"},
		CommonName:   service + " CA",
	}
	usage := x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
	extUsage := []x509.ExtKeyUsage{}

	if cert, e := createCert(name, usage, extUsage, nil); e == nil {
		ca = &CA{
			Raw:     *cert,
			Service: service,
		}
	}
	return
}

func (ca *CA) CreateServerCert() (c *RawCert, e error) {
	name := pkix.Name{
		Organization: []string{"Just Enough"},
		CommonName:   ca.Service,
	}
	usage := x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
	extUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}

	c, e = createCert(name, usage, extUsage, &ca.Raw)

	return
}

func (ca *CA) CreateClientCert(n int) (c *RawCert, e error) {
	name := pkix.Name{
		Organization: []string{"Just Enough"},
		CommonName:   fmt.Sprintf("Client%d", n),
	}
	usage := x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
	extUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}

	c, e = createCert(name, usage, extUsage, &ca.Raw)

	return

}

func createCert(name pkix.Name, usage x509.KeyUsage, extUsage []x509.ExtKeyUsage, signer *RawCert) (c *RawCert, e error) {

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		e = fmt.Errorf("failed to generate serial number: %s", err)
		return
	}

	ecdsaPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		e = fmt.Errorf("Failed to generate ECDSA key: %s", err)
		return
	}

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               name,
		NotBefore:             time.Now(),
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		KeyUsage:              usage,
		ExtKeyUsage:           extUsage,
		BasicConstraintsValid: true,
	}

	derBytes := []byte{}
	if signer == nil {
		// Make this a CA, and then self-sign
		template.IsCA = true
		derBytes, err = x509.CreateCertificate(rand.Reader, &template, &template, &ecdsaPriv.PublicKey, ecdsaPriv)
	} else {
		derBytes, err = x509.CreateCertificate(
			rand.Reader,          // random source
			&template,            // certificate parameters to set
			&signer.Certificate,  // cert to sign with
			&ecdsaPriv.PublicKey, // public key to sign
			signer.PrivateKey,    // key to sign with
		)
	}
	if err != nil {
		e = fmt.Errorf("failed to create certificate: %s", err)
		return
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		e = fmt.Errorf("failed to parse certificate: %s", err)
		return
	}

	if signer == nil {
		// self-signed
		err = cert.CheckSignatureFrom(cert)
	} else {
		err = cert.CheckSignatureFrom(&signer.Certificate)
	}
	if err != nil {
		e = fmt.Errorf("signature verification failed: %s", err)
		return
	}

	c = &RawCert{Certificate: *cert, PrivateKey: ecdsaPriv}
	return
}
