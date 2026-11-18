openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 \
  -nodes -keyout ./cert/key.pem -out ./cert/cert.pem \
  -subj "/CN=127.0.0.1" \
  -addext "subjectAltName=IP:127.0.0.1,DNS:localhost"
