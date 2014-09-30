package enough

import (
	_ "crypto/sha256"
	_ "crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestNewCA(t *testing.T) {
	t.Parallel()
	ca, err := NewCA("testing")
	if err != nil {
		t.Fatalf("failed to create CA: %s", err)
	}
	cacert := ca.Raw.Certificate
	if !cacert.IsCA {
		t.Error("CA cert does not have IsCA set")
	}
	if err := cacert.CheckSignatureFrom(&ca.Raw.Certificate); err != nil {
		t.Errorf("self-signature invalid: %s", err)
	}
}

func TestMarshalRoundtrip(t *testing.T) {
	t.Parallel()
	ca, err := NewCA("testing")
	if err != nil {
		t.Fatalf("failed to create CA: %s", err)
	}
	pemBytes, err := ca.Raw.MarshalCertificate()
	pem, rest := pem.Decode(pemBytes)
	if len(rest) > 0 {
		t.Errorf("extra bytes in pem: % x", rest)
	}
	if got := pem.Type; got != "CERTIFICATE" {
		t.Errorf("expected PEM format CERTIFICATE, got %s", got)
	}

	cert, err := x509.ParseCertificate(pem.Bytes)
	if err != nil {
		t.Errorf("failed to create certificate: %s", err)
	}

	if !cert.Equal(&ca.Raw.Certificate) {
		t.Error("certificates not equal after marshal roundtrip")
	}
}

func TestServerCert(t *testing.T) {
	t.Parallel()
	ca, err := NewCA("testing")
	if err != nil {
		t.Fatalf("failed to create CA: %s", err)
	}

	server, err := ca.CreateServerCert()
	if err != nil {
		t.Fatalf("unable to create server cert: %s", err)
	}
	if err := ca.Raw.Certificate.CheckSignature(x509.ECDSAWithSHA256, server.Certificate.RawTBSCertificate, server.Certificate.Signature); err != nil {
		t.Errorf("CA signature invalid: %s", err)
	}

	serverAuth := false
	for _, u := range server.Certificate.ExtKeyUsage {
		if u == x509.ExtKeyUsageServerAuth {
			serverAuth = true
		}
	}
	if !serverAuth {
		t.Error("server certificate not valid for server auth")
	}

}

func TestClientCerts(t *testing.T) {
	t.Parallel()
	ca, err := NewCA("testing")
	if err != nil {
		t.Fatalf("failed to create CA: %s", err)
	}
	serials := make(map[string]bool)
	for i := 0; i < 1000; i++ {

		c, err := ca.CreateClientCert(i)
		if err != nil {
			t.Fatalf("unable to create client cert: %s", err)
		}

		clientAuth := false
		for _, u := range c.Certificate.ExtKeyUsage {
			if u == x509.ExtKeyUsageClientAuth {
				clientAuth = true
			}
		}
		if !clientAuth {
			t.Error("client certificate not valid for client auth")
		}

		if err := c.Certificate.CheckSignatureFrom(&ca.Raw.Certificate); err != nil {
			t.Errorf("CA signature invalid: %s", err)
		}

		if serials[c.Certificate.SerialNumber.String()] {
			t.Errorf("already seen serial %v", c.Certificate.SerialNumber)
		}
		serials[c.Certificate.SerialNumber.String()] = true

	}
}
