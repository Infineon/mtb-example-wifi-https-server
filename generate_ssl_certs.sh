#!/bin/sh

################################
# Become a Certificate Authority
################################

MY_DOMAIN_NAME=mysecurehttpserver.local

OPENSSL_SUBJECT_INFO="/C=IN/ST=Karnataka/L=Bengaluru/O=CY/OU=Engineering/CN=$MY_DOMAIN_NAME"

# Generate a private root key
openssl genrsa -out rootCA.key 2048

# Self-sign a certificate. Make sure to set the "Common Name" field to match
# your server name (HTTPS_SERVER_NAME) defined in the application.
openssl req -x509 -new -nodes -key rootCA.key -sha256 \
-days 3650 -out rootCA.crt -subj $OPENSSL_SUBJECT_INFO

########################
# Create CA-signed certs
########################

# Generate a private key
openssl genrsa -out $MY_DOMAIN_NAME.key 2048

# Create the Certificate Signing Request (CSR).
# Make sure to set the "Common Name" field with MY_DOMAIN_NAME.
openssl req -new -key $MY_DOMAIN_NAME.key -out $MY_DOMAIN_NAME.csr \
-subj $OPENSSL_SUBJECT_INFO

# Create a config file for the extensions
>$MY_DOMAIN_NAME.ext cat <<-EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names
[alt_names]
DNS.1 = $MY_DOMAIN_NAME
EOF

# Create the signed certificate
openssl x509 -req -in $MY_DOMAIN_NAME.csr -CA rootCA.crt \
-CAkey rootCA.key -CAcreateserial -out $MY_DOMAIN_NAME.crt \
-days 3650 -sha256 -extfile $MY_DOMAIN_NAME.ext

# We have now successfully generated the server certificate ($MY_DOMAIN_NAME.crt) and
# server private key ($MY_DOMAIN_NAME.key). Use them to start your secure server.
# Remove the intermediate files.
rm rootCA.srl $MY_DOMAIN_NAME.csr $MY_DOMAIN_NAME.ext
