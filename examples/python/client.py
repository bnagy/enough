import tempfile
import socket
import ssl

HOST = ('127.0.0.1', 8000)

CERT = tempfile.NamedTemporaryFile(mode='w+t')
CERT.write("""
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
""")
CERT.seek(0, 0)

KEY = tempfile.NamedTemporaryFile(mode='w+t')
KEY.write("""
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIJ9v1AwXN1UcohUPySUt345AnCxyvyAcaaOzMDAvvknXoAoGCCqGSM49
AwEHoUQDQgAEHSFqNVyOJO03U91r8cI72NEOO6dCJozrvLQqxXJ4467/gTlePXnM
+PJnfIh/IEhzOxxRpBM8xfsFJeJ3OSDW9w==
-----END EC PRIVATE KEY-----
""")
KEY.seek(0, 0)

CA = tempfile.NamedTemporaryFile(mode='w+t')
CA.write("""
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
""")
CA.seek(0, 0)

OPTIONS = ssl.OP_NO_COMPRESSION | \
    ssl.OP_NO_SSLv2 | \
    ssl.OP_NO_SSLv3 | \
    ssl.OP_NO_TLSv1 | \
    ssl.OP_NO_TLSv1_1

ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
ctx.verify_mode = ssl.CERT_REQUIRED

ctx.options = OPTIONS
ctx.set_ciphers("ECDHE-ECDSA-AES128-GCM-SHA256")
ctx.load_verify_locations(CA.name)
ctx.load_cert_chain(CERT.name, KEY.name)

ssl_socket = ctx.wrap_socket(socket.socket(socket.AF_INET))
ssl_socket.connect(HOST)

ssl_socket.send(b"HELLO FROM PYTHON\n")
if ssl_socket.recv() == b"ACK\n":
    print("client: received ACK! All done...")
