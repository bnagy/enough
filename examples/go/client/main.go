package main

import (
	"crypto/tls"
	"crypto/x509"
	"log"
)

var clientTestCert = []byte(`
-----BEGIN CERTIFICATE-----
MIIBizCCATCgAwIBAgIQUNkDPUeBoIB/nTnYuA/e6jAKBggqhkjOPQQDAjAtMRQw
EgYDVQQKEwtKdXN0IEVub3VnaDEVMBMGA1UEAxMMVGVzdENlcnRzIENBMCAXDTE0
MTAwMTAxMDcwM1oYDzIxMTQxMDAxMDEwNzAzWjAoMRQwEgYDVQQKEwtKdXN0IEVu
b3VnaDEQMA4GA1UEAxMHQ2xpZW50MDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IA
BJE+Gyvm6d2WeubaWeTpCD4+aiEcODm2tO2GbuML/vvpPuFU3m1bV7L3pim6pam9
wHVakZTuueWFIAhF2Kdp556jNTAzMA4GA1UdDwEB/wQEAwIAoDATBgNVHSUEDDAK
BggrBgEFBQcDAjAMBgNVHRMBAf8EAjAAMAoGCCqGSM49BAMCA0kAMEYCIQDk7oK6
QixHXY7bqW4sl0xSr2GaIP8kM8JejQANnqWCyQIhAI2YxXLe9wb5rQqhBGmGus4V
ijdCNsxTk7nnJp7i13fv
-----END CERTIFICATE-----
`)

var clientTestKey = []byte(`
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIBTWPGLcNC7yJ8wtkNPWyEOXoiStLV5k2oFBJSpzXcm0oAoGCCqGSM49
AwEHoUQDQgAEkT4bK+bp3ZZ65tpZ5OkIPj5qIRw4Oba07YZu4wv+++k+4VTebVtX
svemKbqlqb3AdVqRlO655YUgCEXYp2nnng==
-----END EC PRIVATE KEY-----
`)

var caTestCert = []byte(`
-----BEGIN CERTIFICATE-----
MIIBfTCCASSgAwIBAgIRAKxpQXQltTmMEBz8cVJ1w3IwCgYIKoZIzj0EAwIwLTEU
MBIGA1UEChMLSnVzdCBFbm91Z2gxFTATBgNVBAMTDFRlc3RDZXJ0cyBDQTAgFw0x
NDEwMDEwMTA3MDNaGA8yMTE0MTAwMTAxMDcwM1owLTEUMBIGA1UEChMLSnVzdCBF
bm91Z2gxFTATBgNVBAMTDFRlc3RDZXJ0cyBDQTBZMBMGByqGSM49AgEGCCqGSM49
AwEHA0IABHUHF2fjaMA97qT/0vapZ2IuKNA5GgM/LbpMqMBwR6s8sG0EpKqidLN0
J3BjsoGRghy34Csng8Tg1rsdI7WRNvyjIzAhMA4GA1UdDwEB/wQEAwIApDAPBgNV
HRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIDjjXN9rEIbMEVAu0SFDxyvJ
sXRHl0avpROUFvOE7hh/AiBhSjYbohfDw1JSZ3Psz7Tc7plvx2ATIxISKMBaHxE+
fA==
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

	conn, err := tls.Dial("tcp", "[::1]:8000", config)
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
