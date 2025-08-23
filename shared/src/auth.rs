use anyhow::{Context, Result};
use rustls::{
    ServerConfig, ClientConfig, RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, PrivatePkcs1KeyDer, PrivateSec1KeyDer}
};
use rustls::server::WebPkiClientVerifier;
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use axum_server::tls_rustls::RustlsConfig;

// Authentifie les agents via mTLS
pub fn build_server_mtls_config(
    server_cert_path: &str,
    server_key_path: &str,
    client_ca_path: &str,
) -> Result<RustlsConfig> {
    println!("🔐 Configuration mTLS du serveur S3...");
    
    let cert_chain = load_certs(server_cert_path)
        .context("Erreur chargement certificat serveur")?;
    
    let private_key = load_private_key(server_key_path)
        .context("Erreur chargement clé privée serveur")?;
    
    let client_ca_store = load_ca_store(client_ca_path)
        .context("Erreur chargement CA client")?;
    
    // Verificateur pour MTLS agents
    let client_verifier = WebPkiClientVerifier::builder(Arc::new(client_ca_store))
        .build()
        .context("Erreur création vérificateur CA agents")?;
    
    // On construit la configuration du serveur avec les certificats et le vérificateur
    let mut server_config = ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(cert_chain, private_key)
        .context("Erreur configuration certificats serveur")?;
    
    // On active aussi HTTP/2
    server_config.alpn_protocols = vec![
        b"h2".to_vec(),
        b"http/1.1".to_vec(),
    ];
    
    println!("✅ Configuration mTLS pour serveur S3 terminée");
    Ok(RustlsConfig::from_config(Arc::new(server_config)))
}

// Configuration mTLS pour Client (agents), s'authentifie auprès du serveur via mTLS
pub fn build_client_mtls_config(
    client_cert_path: &str,
    client_key_path: &str,
    server_ca_path: &str,
) -> Result<ClientConfig> {
    println!("🔐 Configuration mTLS client...");
    
    let cert_chain = load_certs(client_cert_path)
        .context("Erreur chargement certificat client")?;
    
    let private_key = load_private_key(client_key_path)
        .context("Erreur chargement clé privée client")?;
    
    let server_ca_store = load_ca_store(server_ca_path)
        .context("Erreur chargement CA serveur")?;
    
    // Configuration client avec mTLS
    let client_config = ClientConfig::builder()
        .with_root_certificates(server_ca_store)  // Vérifie le serveur
        .with_client_auth_cert(cert_chain, private_key)  // S'authentifie
        .context("Erreur configuration certificats client")?;
    
    println!("✅ Configuration mTLS pour Agents terminée");
    Ok(client_config)
}

// Pour charger une chaîne de certificats depuis un fichier PEM
pub fn load_certs(cert_path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let cert_file = File::open(cert_path)
        .with_context(|| format!("Impossible d'ouvrir le fichier de certificat: {}", cert_path))?;
    let mut reader = BufReader::new(cert_file);
    
    let certs = rustls_pemfile::certs(&mut reader)
        .with_context(|| format!("Erreur lecture certificats de {}", cert_path))?
        .into_iter()
        .map(CertificateDer::from)
        .collect();
    
    Ok(certs)
}

// Pour charger une clé privée depuis un fichier PEM
pub fn load_private_key(key_path: &str) -> Result<PrivateKeyDer<'static>> {
    // PKCS#8
    {
        let mut reader = BufReader::new(File::open(key_path)?);
        if let Ok(mut keys) = rustls_pemfile::pkcs8_private_keys(&mut reader) {
            if let Some(key) = keys.into_iter().next() {
                return Ok(PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key)));
            }
        }
    }
    
    // PKCS#1
    {
        let mut reader = BufReader::new(File::open(key_path)?);
        if let Ok(mut keys) = rustls_pemfile::rsa_private_keys(&mut reader) {
            if let Some(key) = keys.into_iter().next() {
                return Ok(PrivateKeyDer::from(PrivatePkcs1KeyDer::from(key)));
            }
        }
    }
    
    // SEC1 
    {
        let mut reader = BufReader::new(File::open(key_path)?);
        if let Ok(mut keys) = rustls_pemfile::ec_private_keys(&mut reader) {
            if let Some(key) = keys.into_iter().next() {
                return Ok(PrivateKeyDer::from(PrivateSec1KeyDer::from(key)));
            }
        }
    }
    
    anyhow::bail!("Aucune clé privée trouvée dans {}", key_path);
}

// Pour charger un store de certificats CA depuis un fichier PEM
pub fn load_ca_store(ca_path: &str) -> Result<RootCertStore> {
    let mut reader = BufReader::new(File::open(ca_path)
        .with_context(|| format!("Impossible d'ouvrir le fichier CA: {}", ca_path))?);
    
    let mut store = RootCertStore::empty();
    let certs = rustls_pemfile::certs(&mut reader)
        .with_context(|| format!("Erreur lecture certificats CA de {}", ca_path))?;
    
    for cert_der in certs {
        store.add(CertificateDer::from(cert_der))
            .with_context(|| format!("Erreur ajout certificat CA depuis {}", ca_path))?;
    }
    
    Ok(store)
}

// Configuration serveur TLS uniquement pour les clients S3 qui n'ont pas de certificat (AWS CLI etc)
pub fn build_server_tls_config(
    server_cert_path: &str,
    server_key_path: &str,
) -> Result<RustlsConfig> {
    println!("🔓 Configuration TLS serveur standard...");
    
    let cert_chain = load_certs(server_cert_path)
        .context("Erreur chargement certificat serveur")?;
    
    let private_key = load_private_key(server_key_path)
        .context("Erreur chargement clé privée serveur")?;
    
    // Configuration serveur sans vérification client
    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()  // ← Pas de certificat client requis
        .with_single_cert(cert_chain, private_key)
        .context("Erreur configuration certificats serveur")?;
    
    // Support HTTP/2
    server_config.alpn_protocols = vec![
        b"h2".to_vec(),
        b"http/1.1".to_vec(),
    ];
    
    println!("✅ Configuration TLS serveur standard terminée");
    Ok(RustlsConfig::from_config(Arc::new(server_config)))
}