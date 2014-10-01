package main

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"net"
)

var serverTestCert = []byte(`
-----BEGIN CERTIFICATE-----
MIIBjjCCATOgAwIBAgIRAJTGaie8XKKOLMnppGwpJTkwCgYIKoZIzj0EAwIwLTEU
MBIGA1UEChMLSnVzdCBFbm91Z2gxFTATBgNVBAMTDFRlc3RDZXJ0cyBDQTAgFw0x
NDEwMDEwMTA3MDNaGA8yMTE0MTAwMTAxMDcwM1owKjEUMBIGA1UEChMLSnVzdCBF
bm91Z2gxEjAQBgNVBAMTCVRlc3RDZXJ0czBZMBMGByqGSM49AgEGCCqGSM49AwEH
A0IABLjTxuBmpzfqd1wpcdBohm1510JRA5gdY5OPltFb8x9GFj0ctxEOkodnxUSK
Ggg+zD29h6Sa1NPfQh4nP95aZIijNTAzMA4GA1UdDwEB/wQEAwIAoDATBgNVHSUE
DDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMAoGCCqGSM49BAMCA0kAMEYCIQDc
sXNUtQVq8/wBgn6PhR7pJHGIhda8GVS/6sFUwyX7RQIhANeTAotHIOgEhCVKNHdM
x6hlcQyLX3Bf1t6RO88Z2ZMx
-----END CERTIFICATE-----
`)

var serverTestKey = []byte(`
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIIdWzPJP1OkbGGDGPJ9FWYdR5VaFGDa3zjbi5Nw6Gqf5oAoGCCqGSM49
AwEHoUQDQgAEuNPG4GanN+p3XClx0GiGbXnXQlEDmB1jk4+W0VvzH0YWPRy3EQ6S
h2fFRIoaCD7MPb2HpJrU099CHic/3lpkiA==
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

func sendAck(conn net.Conn) {
	defer conn.Close()
	conn.Write([]byte("ACK\n"))
}

func main() {

	cert, err := tls.X509KeyPair(serverTestCert, serverTestKey)
	if err != nil {
		log.Fatalf("server: failed to load keys: %s", err)
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(caTestCert) {
		log.Fatalf("server: failed to load cert pool")
	}

	config := &tls.Config{
		ClientCAs:              certPool,
		ClientAuth:             tls.RequireAndVerifyClientCert,
		Certificates:           []tls.Certificate{cert},
		MinVersion:             tls.VersionTLS12,
		SessionTicketsDisabled: true,
		CipherSuites:           []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
	}
	log.Printf("server: loaded TLS config and certs")

	listener, err := tls.Listen("tcp", "[::1]:8000", config)
	if err != nil {
		log.Fatalf("server: failed to listen: %s", err)
	}
	log.Printf("server: started listener")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatalf("error in accept: %s", err)
			break
		}
		log.Printf("server: accepted %s", conn.RemoteAddr().String())
		go sendAck(conn)
	}

}
