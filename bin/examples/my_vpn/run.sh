#!/bin/bash

OPENSSL_CONF_FILE="openssl.conf"
KEY_FILE_NAME="key.pem"
CERT_FILE_NAME="cert.pem"
VPN_CONF_FILE="vpn.conf"

if [ ! -f "$KEY_FILE_NAME" ] || [ ! -f "$CERT_FILE_NAME" ]; then
    openssl req -config "$OPENSSL_CONF_FILE" -new -x509 -sha256 -newkey rsa:2048 -nodes -days 1000 \
    -keyout "$KEY_FILE_NAME" -out "$CERT_FILE_NAME"
fi

cargo run --package vpn_endpoint --bin vpn_endpoint "$VPN_CONF_FILE"
