
openssl ecparam -genkey -name prime256v1 -out cert-key-ecdsa.pem
openssl req -new -sha256 -key cert-key-ecdsa.pem -out cert-ecdsa.csr
openssl req -x509 -sha256 -days 365 -key cert-key-ecdsa.pem -in cert-ecdsa.csr -out cert-ecdsa.pem
openssl req -in cert-ecdsa.csr -text -noout | grep -i "Signature.*SHA256" && echo "All is well"

