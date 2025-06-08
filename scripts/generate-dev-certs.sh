#!/bin/bash

# Supacrypt Development Certificate Generation Script
# This script generates a complete certificate infrastructure for development and testing

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="${SCRIPT_DIR}/../certs"
CA_DAYS=365
CERT_DAYS=365
KEY_SIZE=4096

echo "Creating certificate directory: ${CERTS_DIR}"
mkdir -p "${CERTS_DIR}"
cd "${CERTS_DIR}"

# Clean up existing certificates
echo "Cleaning up existing certificates..."
rm -f *.pem *.pfx *.key *.crt *.srl

echo "Generating development certificates for Supacrypt..."

# 1. Generate Root CA
echo "Step 1: Generating Root CA..."
openssl req -x509 -newkey rsa:${KEY_SIZE} -days ${CA_DAYS} -nodes \
    -keyout ca-key.pem -out ca-cert.pem \
    -subj "/C=US/ST=State/L=City/O=Supacrypt/CN=Supacrypt Dev CA"

echo "Root CA generated: ca-cert.pem"

# 2. Generate Server Certificate
echo "Step 2: Generating Server Certificate..."
openssl req -newkey rsa:${KEY_SIZE} -nodes -keyout server-key.pem \
    -out server-req.pem \
    -subj "/C=US/ST=State/L=City/O=Supacrypt/CN=localhost"

# Create server certificate extensions
cat > server-ext.conf << EOF
subjectAltName = @alt_names
extendedKeyUsage = serverAuth

[alt_names]
DNS.1 = localhost
DNS.2 = *.localhost
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

openssl x509 -req -in server-req.pem -days ${CERT_DAYS} \
    -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial \
    -out server-cert.pem \
    -extfile server-ext.conf

# Convert server certificate to PFX format
openssl pkcs12 -export -out server-cert.pfx \
    -inkey server-key.pem -in server-cert.pem \
    -passout pass:

echo "Server certificate generated: server-cert.pem, server-cert.pfx"

# 3. Function to generate client certificates
generate_client_cert() {
    local provider=$1
    local role=${2:-"User"}
    
    echo "Generating client certificate for ${provider}..."
    
    # Generate client certificate request
    openssl req -newkey rsa:${KEY_SIZE} -nodes -keyout ${provider}-key.pem \
        -out ${provider}-req.pem \
        -subj "/C=US/ST=State/L=City/O=Supacrypt/OU=${role}/CN=${provider}"
    
    # Create client certificate extensions
    cat > ${provider}-ext.conf << EOF
extendedKeyUsage = clientAuth
keyUsage = digitalSignature, keyEncipherment
EOF
    
    # Sign the client certificate
    openssl x509 -req -in ${provider}-req.pem -days ${CERT_DAYS} \
        -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial \
        -out ${provider}-cert.pem \
        -extfile ${provider}-ext.conf
    
    # Convert to PFX format
    openssl pkcs12 -export -out ${provider}-cert.pfx \
        -inkey ${provider}-key.pem -in ${provider}-cert.pem \
        -passout pass:
    
    echo "Client certificate generated for ${provider}: ${provider}-cert.pem, ${provider}-cert.pfx"
    
    # Clean up temporary files
    rm -f ${provider}-req.pem ${provider}-ext.conf
}

# 4. Generate client certificates for each provider
echo "Step 3: Generating Client Certificates..."
generate_client_cert "PKCS11" "User"
generate_client_cert "CSP" "User"
generate_client_cert "KSP" "User"
generate_client_cert "CTK" "User"

# 5. Generate admin certificate
echo "Step 4: Generating Admin Certificate..."
generate_client_cert "Admin" "Admin"

# 6. Generate test client certificate
echo "Step 5: Generating Test Client Certificate..."
generate_client_cert "TestClient" "User"

# 7. Clean up temporary files
rm -f server-req.pem server-ext.conf *.srl

# 8. Generate certificate information
echo "Step 6: Generating certificate information..."
cat > certificate-info.txt << EOF
Supacrypt Development Certificates
==================================

Generated on: $(date)
Certificate Authority: Supacrypt Dev CA
Validity Period: ${CERT_DAYS} days
Key Size: ${KEY_SIZE} bits

Files Generated:
================

Root CA:
- ca-cert.pem (Root CA certificate - install as trusted root)
- ca-key.pem (Root CA private key - keep secure)

Server Certificate:
- server-cert.pem (Server certificate)
- server-cert.pfx (Server certificate in PFX format, no password)
- server-key.pem (Server private key)

Client Certificates:
- PKCS11-cert.pem/.pfx (PKCS11 provider certificate)
- CSP-cert.pem/.pfx (CSP provider certificate)
- KSP-cert.pem/.pfx (KSP provider certificate)
- CTK-cert.pem/.pfx (CTK provider certificate)
- Admin-cert.pem/.pfx (Admin certificate with elevated privileges)
- TestClient-cert.pem/.pfx (General test client certificate)

Certificate Thumbprints:
========================
EOF

# Generate thumbprints for easy configuration
for cert in *.pem; do
    if [[ $cert == *"-cert.pem" ]]; then
        thumbprint=$(openssl x509 -in "$cert" -fingerprint -sha1 -noout | cut -d= -f2 | tr -d :)
        echo "${cert%%-cert.pem}: ${thumbprint}" >> certificate-info.txt
    fi
done

echo ""
echo "Development certificates generated successfully!"
echo "Certificates location: ${CERTS_DIR}"
echo ""
echo "Configuration for appsettings.Development.json:"
echo "================================================"
cat << EOF
{
  "Security": {
    "Mtls": {
      "Enabled": false,
      "CheckCertificateRevocation": false,
      "AllowedThumbprints": [
EOF

# Output thumbprints for configuration
first=true
for cert in *-cert.pem; do
    if [[ $cert != "ca-cert.pem" && $cert != "server-cert.pem" ]]; then
        thumbprint=$(openssl x509 -in "$cert" -fingerprint -sha1 -noout | cut -d= -f2 | tr -d :)
        if [ "$first" = true ]; then
            echo "        \"${thumbprint}\""
            first=false
        else
            echo "        ,\"${thumbprint}\""
        fi
    fi
done

cat << EOF
      ]
    },
    "ServerCertificate": {
      "Source": "File",
      "Path": "certs/server-cert.pfx",
      "Password": ""
    }
  }
}
EOF

echo ""
echo "IMPORTANT SECURITY NOTES:"
echo "========================="
echo "1. These certificates are for DEVELOPMENT ONLY"
echo "2. Never use these certificates in production"
echo "3. The CA private key (ca-key.pem) should be kept secure"
echo "4. Install ca-cert.pem as a trusted root CA in your development environment"
echo "5. All certificates have no password for development convenience"
echo ""
echo "Certificate information saved to: certificate-info.txt"