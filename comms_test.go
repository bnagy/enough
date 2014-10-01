package enough

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
)

func sendAck(conn net.Conn) {
	defer conn.Close()
	conn.Write([]byte("ACK\n"))
}

func serverListen(sem chan struct{}, t *testing.T) {

	cert, err := tls.X509KeyPair(serverTestCert, serverTestKey)
	if err != nil {
		t.Errorf("server: failed to load keys: %s", err)
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(caTestCert) {
		t.Errorf("server: failed to load cert pool")
	}

	config := &tls.Config{
		ClientCAs:              certPool,
		ClientAuth:             tls.RequireAndVerifyClientCert,
		Certificates:           []tls.Certificate{cert},
		MinVersion:             tls.VersionTLS12,
		SessionTicketsDisabled: true,
		CipherSuites:           []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
	}
	listener, err := tls.Listen("tcp", "[::1]:8000", config)
	if err != nil {
		t.Errorf("server: failed to listen: %s", err)
	}

	close(sem)

	for {
		conn, err := listener.Accept()
		if err != nil {
			t.Errorf("error in accept: %s", err)
			break
		}
		go sendAck(conn)
	}

}

func TestComms(t *testing.T) {
	t.Parallel()
	sem := make(chan struct{})
	go serverListen(sem, t)
	<-sem

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(caTestCert) {
		t.Fatalf("client: failed to load cert pool")
	}

	cert, err := tls.X509KeyPair(clientTestCert, clientTestKey)
	if err != nil {
		t.Fatalf("client: failed to load keys: %s", err)
	}

	config := &tls.Config{
		RootCAs:                certPool,
		Certificates:           []tls.Certificate{cert},
		MinVersion:             tls.VersionTLS12,
		SessionTicketsDisabled: true,
		ServerName:             "TestCerts",
		CipherSuites:           []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
	}

	conn, err := tls.Dial("tcp", "[::1]:8000", config)
	if err != nil {
		t.Fatalf("client: failed to dial: %s", err)
	}
	defer conn.Close()

	resp := make([]byte, 4)
	conn.Read(resp)
	if string(resp) != "ACK\n" {
		t.Fatalf("client: unexpected response: want ACK, got % x", resp)
	}

}
