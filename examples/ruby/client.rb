require 'openssl'
require 'socket'

include OpenSSL::SSL

HOST = '127.0.0.1'
PORT = 8000

CERT = OpenSSL::X509::Certificate.new "
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
"

KEY = OpenSSL::PKey::EC.new "
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIJ9v1AwXN1UcohUPySUt345AnCxyvyAcaaOzMDAvvknXoAoGCCqGSM49
AwEHoUQDQgAEHSFqNVyOJO03U91r8cI72NEOO6dCJozrvLQqxXJ4467/gTlePXnM
+PJnfIh/IEhzOxxRpBM8xfsFJeJ3OSDW9w==
-----END EC PRIVATE KEY-----
"

CA = OpenSSL::X509::Certificate.new "
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
"

# Disable session tickets and compression
opts = [
  OP_NO_COMPRESSION,
  OP_NO_SSLv2,
  OP_NO_SSLv3,
  OP_NO_TLSv1,
  OP_NO_TLSv1_1,
  OP_NO_TICKET,
  VERIFY_FAIL_IF_NO_PEER_CERT
]

# Don't use the system root certs, just use our one hardcoded CA. Only certs
# that are signed by this CA should be allowed.
store = OpenSSL::X509::Store.new
store.add_cert(CA)

# Set up the OpenSSL "context" which configures a myriad of confusing options.
ctx = SSLContext.new :TLSv1_2
ctx.options = opts.inject(&:|)
ctx.cert = CERT
ctx.key = KEY
ctx.cert_store = store
# This is the best suite supported by the Go server
ctx.ciphers = "ECDHE-ECDSA-AES128-GCM-SHA256"
# No peer verification is done without this!
ctx.verify_mode = OpenSSL::SSL::VERIFY_PEER
# Our server will be signed by the CA, not self-signed ( which would be depth 0 )
ctx.verify_depth = 1
# Debugging tip - the openssl errors can be stupidly terse, but sometimes the
# verification callback lets you get a better error string.
# ctx.verify_callback = lambda {|passed,ctx|
#   puts ctx.error_string unless passed
#   passed
# }

socket = TCPSocket.new(HOST, PORT)
ssl = SSLSocket.new(socket, ctx)
ssl.sync_close = true
ssl.connect

ssl.write "HELLO FROM RUBBY\n"
if ssl.readline == "ACK\n"
  puts "client: received ACK! All done..."
end
