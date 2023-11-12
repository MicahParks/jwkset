openssl req -newkey EC -pkeyopt ec_paramgen_curve:P-521 -noenc -keyout ec521.pem -x509 -out ec521.crt -subj "/C=US/ST=Virginia/L=Richmond/O=Micah Parks/OU=Self/CN=example.com"
openssl req -newkey ED25519 -noenc -keyout ed25519.pem -x509 -out ed25519.crt -subj "/C=US/ST=Virginia/L=Richmond/O=Micah Parks/OU=Self/CN=example.com"
openssl req -newkey RSA:4096 -noenc -keyout rsa4096.pem -x509 -out rsa4096.crt -subj "/C=US/ST=Virginia/L=Richmond/O=Micah Parks/OU=Self/CN=example.com"
