#!/bin/bash
set -e

echo "🔧 Génération des certificats RustyKey..."

# Dossiers de destination pour les certificats
AGENT_DIR="agent"
BACKEND_DIR="backend"
MINIO_CERTS_DIR="minio-certs"

# Nettoyage complet des anciens certificats et clés
echo "🗑️ Suppression de tous les anciens certificats et dossiers..."
rm -rf "$AGENT_DIR" "$BACKEND_DIR" "$MINIO_CERTS_DIR"
rm -f ca.crt ca.key ca.srl *.csr *.ext
echo "✅ Nettoyage terminé."

# Création des dossiers de destination
mkdir -p "$AGENT_DIR"
mkdir -p "$BACKEND_DIR"
mkdir -p "$MINIO_CERTS_DIR/CAs"

# 1. Création de la CA racine (identique à votre CA fonctionnelle)
echo "🔑 Création de la nouvelle CA racine..."
openssl genrsa -out ca.key 4096
openssl req -new -x509 -key ca.key -sha256 -days 3650 \
    -subj "/C=FR/ST=PACA/O=RustyKey/CN=RustyKey-CA" \
    -out ca.crt
echo "✅ CA racine créée."

# Distribution de la CA
cp ca.crt "$AGENT_DIR/ca.crt"
cp ca.crt "$BACKEND_DIR/ca.crt"
cp ca.crt "$MINIO_CERTS_DIR/CAs/ca.crt"
echo "✅ CA racine copiée dans tous les dossiers requis."

# 2. Génération du certificat Backend (identique à votre certificat fonctionnel)
echo "🔐 Génération des certificats pour le backend..."
openssl genrsa -out "$BACKEND_DIR/backend.key" 4096

# Création du fichier de configuration pour le backend (reproduit exactement votre certificat)
cat > backend.conf <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C=FR
ST=PACA
L=Aix-en-Provence
O=RustyKey
OU=Backend
CN=rustykey-backend.local

[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = rustykey-backend.local
DNS.2 = localhost
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

openssl req -new -key "$BACKEND_DIR/backend.key" -out backend.csr -config backend.conf

openssl x509 -req -in backend.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out "$BACKEND_DIR/backend.crt" -days 365 -sha256 \
    -extensions v3_req -extfile backend.conf

echo "✅ Certificat du backend créé avec succès."

# 3. Génération du certificat Agent
echo "🔐 Génération des certificats pour l'agent..."
openssl genrsa -out "$AGENT_DIR/agent.key" 4096

# Création du fichier de configuration pour l'agent
cat > agent.conf <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C=FR
ST=PACA
O=RustyKey
CN=rustykey-agent

[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = rustykey-agent.local
DNS.2 = localhost
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

openssl req -new -key "$AGENT_DIR/agent.key" -out agent.csr -config agent.conf

openssl x509 -req -in agent.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out "$AGENT_DIR/agent.crt" -days 365 -sha256 \
    -extensions v3_req -extfile agent.conf

echo "✅ Certificat de l'agent créé avec succès."

# 4. Génération du certificat Webhook (pour le client MinIO)
echo "🔐 Génération des certificats pour le webhook MinIO..."
openssl genrsa -out "$MINIO_CERTS_DIR/webhook.key" 4096

# Configuration simple pour webhook (pas de SAN)
cat > webhook.conf <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C=FR
ST=PACA
O=RustyKey
CN=minio-webhook

[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF

openssl req -new -key "$MINIO_CERTS_DIR/webhook.key" -out webhook.csr -config webhook.conf

openssl x509 -req -in webhook.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out "$MINIO_CERTS_DIR/webhook.crt" -days 365 -sha256 -extensions v3_req -extfile webhook.conf

echo "✅ Certificat du webhook créé avec succès."

# Configuration des permissions
echo "🔒 Configuration des permissions..."
chmod 600 "$BACKEND_DIR/backend.key" "$AGENT_DIR/agent.key" "$MINIO_CERTS_DIR/webhook.key"
chmod 644 "$BACKEND_DIR/backend.crt" "$AGENT_DIR/agent.crt" "$MINIO_CERTS_DIR/webhook.crt"
chmod 644 "$BACKEND_DIR/ca.crt" "$AGENT_DIR/ca.crt" "$MINIO_CERTS_DIR/CAs/ca.crt"

# Nettoyage des fichiers intermédiaires
rm -f ca.srl *.csr *.conf

echo ""
echo "✅ Certificats générés avec succès !"
echo ""
echo "📁 Structure créée :"
echo "   backend/: backend.crt, backend.key, ca.crt"
echo "   agent/: agent.crt, agent.key, ca.crt"
echo "   minio-certs/CAs/: webhook.crt, webhook.key, ca.crt"
echo ""


# Nettoyage final
rm -f ca.key ca.crt