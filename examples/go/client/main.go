package main

import (
	"crypto/tls"
	"crypto/x509"
	"log"
)

var clientTestCert = []byte(`
-----BEGIN CERTIFICATE-----
MIIBiTCCAS6gAwIBAgIQc5xt4hCgFJUFhloTJ3u4zTAKBggqhkjOPQQDAjAtMRQw
EgYDVQQKEwtKdXN0IEVub3VnaDEVMBMGA1UEAxMMVGVzdENlcnRzIENBMB4XDTE0
MTAwMjAzMDczMVoXDTI0MTAwMjAzMDczMVowKDEUMBIGA1UEChMLSnVzdCBFbm91
Z2gxEDAOBgNVBAMTB0NsaWVudDAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQd
IWo1XI4k7TdT3WvxwjvY0Q47p0ImjOu8tCrFcnjjrv+BOV49ecz48md8iH8gSHM7
HFGkEzzF+wUl4nc5INb3ozUwMzAOBgNVHQ8BAf8EBAMCAKAwEwYDVR0lBAwwCgYI
KwYBBQUHAwIwDAYDVR0TAQH/BAIwADAKBggqhkjOPQQDAgNJADBGAiEAr/cG+UJa
jptZlk3wPOyeiOYbwf1TwYELg/HPS+Cw/i0CIQD6pU2ly8ke3kRedkYg8c/IcQzk
6ix4Z6xHx3kojMttkw==
-----END CERTIFICATE-----
`)

var clientTestKey = []byte(`
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIJ9v1AwXN1UcohUPySUt345AnCxyvyAcaaOzMDAvvknXoAoGCCqGSM49
AwEHoUQDQgAEHSFqNVyOJO03U91r8cI72NEOO6dCJozrvLQqxXJ4467/gTlePXnM
+PJnfIh/IEhzOxxRpBM8xfsFJeJ3OSDW9w==
-----END EC PRIVATE KEY-----
`)

var caTestCert = []byte(`
-----BEGIN CERTIFICATE-----
MIIBfDCCASKgAwIBAgIRAKqo7EFuiweGy/wltnbBOqUwCgYIKoZIzj0EAwIwLTEU
MBIGA1UEChMLSnVzdCBFbm91Z2gxFTATBgNVBAMTDFRlc3RDZXJ0cyBDQTAeFw0x
NDEwMDIwMzA3MzFaFw0yNDEwMDIwMzA3MzFaMC0xFDASBgNVBAoTC0p1c3QgRW5v
dWdoMRUwEwYDVQQDEwxUZXN0Q2VydHMgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMB
BwNCAATckejF1hwhYAFFRDS931SIlITeyQPl+WlklErF1eAGH3xNYJ//qS+444Kt
lE9eELUBJxMRf/kpJTDCn0wTz64SoyMwITAOBgNVHQ8BAf8EBAMCAKQwDwYDVR0T
AQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiAkNkA32uE0Ml4qS3Sc4Ktku/Wb
ByqYWPq5RQThpZ3KCQIhAJrvGiN84yVYV+FACSQ4XXuuNWxjI+8L1QjYDIonteX3
-----END CERTIFICATE-----
`)

func main() {

	// By creating our own cert pool, we disable the default pool ( which is
	// all the certs in the OS root certificate store. )
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(caTestCert) {
		log.Fatalf("client: failed to load cert pool")
	}

	cert, err := tls.X509KeyPair(clientTestCert, clientTestKey)
	if err != nil {
		log.Fatalf("client: failed to load keys: %s", err)
	}

	config := &tls.Config{
		RootCAs:                certPool,
		Certificates:           []tls.Certificate{cert},
		MinVersion:             tls.VersionTLS12,
		SessionTicketsDisabled: true,
		ServerName:             "TestCerts",
		CipherSuites:           []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
	}
	log.Printf("client: loaded TLS config and certs")

	conn, err := tls.Dial("tcp", "127.0.0.1:8000", config)
	if err != nil {
		log.Fatalf("client: failed to dial: %s", err)
	}
	defer conn.Close()
	log.Printf("client: connected to server")

	resp := make([]byte, 4)
	conn.Read(resp)
	if string(resp) != "ACK\n" {
		log.Fatalf("client: unexpected response: want ACK, got % x", resp)
	}
	log.Printf("client: received ACK! All done...")
}
