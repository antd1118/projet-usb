#!/bin/bash

set -e

# 1. Créer la CA racine (si pas déjà fait)
openssl genrsa -out ca.key 4096
openssl req -new -x509 -key ca.key -sha256 -days 3650 \
    -subj "/C=FR/ST=PACA/O=RustyKey/CN=RustyKey-CA" \
    -out ca.crt

# 2. Fichier d'extensions v3 pour le backend
cat > backend_v3.ext <<EOF
basicConstraints = CA:FALSE
subjectAltName = @alt_names

[alt_names]
DNS.1 = rustykey-backend.local
EOF

# 3. Certificat backend (clé + CSR + signature v3)
openssl genrsa -out backend.key 4096
openssl req -new -key backend.key -out backend.csr \
    -subj "/C=FR/ST=PACA/O=RustyKey/CN=rustykey-backend.local"
openssl x509 -req -in backend.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out backend.crt -days 365 -sha256 -extfile backend_v3.ext

# 4. Fichier d'extensions v3 pour l'agent
cat > agent_v3.ext <<EOF
basicConstraints = CA:FALSE
subjectAltName = @alt_names

[alt_names]
DNS.1 = 127.0.0.1:7878
EOF

# 5. Certificat agent (clé + CSR + signature v3)
openssl genrsa -out agent.key 4096
openssl req -new -key agent.key -out agent.csr \
    -subj "/C=FR/ST=PACA/O=RustyKey/CN=rustykey-agent"
openssl x509 -req -in agent.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out agent.crt -days 365 -sha256 -extfile agent_v3.ext

echo "Tous les certificats et clés sont prêts !"
echo
echo "→ Vérifie la version de tes certs : doit afficher 'Version: 3 (0x2)'"
echo "  openssl x509 -in backend.crt -noout -text | grep 'Version'"
echo "  openssl x509 -in agent.crt -noout -text | grep 'Version'"
