package main

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"net"
)

var serverTestCert = []byte(`
-----BEGIN CERTIFICATE-----
MIIBizCCATCgAwIBAgIQRscrDbJn2bLiEYKuFxrrijAKBggqhkjOPQQDAjAtMRQw
EgYDVQQKEwtKdXN0IEVub3VnaDEVMBMGA1UEAxMMVGVzdENlcnRzIENBMB4XDTE0
MTAwMjAzMDczMVoXDTI0MTAwMjAzMDczMVowKjEUMBIGA1UEChMLSnVzdCBFbm91
Z2gxEjAQBgNVBAMTCVRlc3RDZXJ0czBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IA
BKrfZiEm+FuSljLbP21778TPCMnv1e1k8jHgIGIWC2DxLBCkXWu435Vm+NL7EkoI
C296vkQi8RNZwNEfvFlcUxejNTAzMA4GA1UdDwEB/wQEAwIAoDATBgNVHSUEDDAK
BggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMAoGCCqGSM49BAMCA0kAMEYCIQCXUtZG
0vHdZLrEkmQYtyVe63LOpDJiEKd3sa8Awxqz7gIhAOZ5Rjd61zF16nvJnlCblnzT
xsSPM9P4vD8zcG5+gpoR
-----END CERTIFICATE-----
`)

var serverTestKey = []byte(`
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFvuDl4S9lyJaRoCzSVQs22C0BATvcH3u6Zzu3i7+wGAoAoGCCqGSM49
AwEHoUQDQgAEqt9mISb4W5KWMts/bXvvxM8Iye/V7WTyMeAgYhYLYPEsEKRda7jf
lWb40vsSSggLb3q+RCLxE1nA0R+8WVxTFw==
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

	listener, err := tls.Listen("tcp", "127.0.0.1:8000", config)
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
