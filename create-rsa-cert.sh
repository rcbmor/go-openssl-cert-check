
openssl genrsa -des3 -passout pass:x -out pass.key 2048
openssl rsa -passin pass:x -in pass.key -out cert-key-rsa.pem
openssl req -new -sha256 -key cert-key-rsa.pem -out cert-rsa.csr
openssl x509 -req -sha256 -days 365 -in cert-rsa.csr -signkey cert-key-rsa.pem -out cert-rsa.pem

#openssl req -newkey rsa:2048 \
#  -new -nodes -x509 \
#  -days 3650 \
#  -out cert.pem \
#  -keyout key.pem \
#  -subj "/C=BR/ST=Rio Grande do Sul/L=Porto Alegre/O=Ricardo Moreira/OU=Your Unit/CN=localhost"

