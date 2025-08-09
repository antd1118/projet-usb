use std::path::{Path, PathBuf};
use tokio::{
    fs,
    net::TcpListener,
};
use serde::{Serialize, Deserialize};
use anyhow::{Context, Result};
use aws_credential_types::Credentials;
use aws_sdk_s3::{primitives::ByteStream, Client};
use aws_types::region::Region;
use axum::{
    routing::post, 
    Json, 
    Router,
    http::StatusCode,
};
use std::fs::create_dir_all;
use tokio::sync::broadcast;
use serde_json::json;
use base64::{engine::general_purpose, Engine as _};
use axum_server::tls_rustls::RustlsConfig;
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
};
use rustls::{RootCertStore, ServerConfig};
use rustls::server::WebPkiClientVerifier;
use rustls_pemfile as pem;

#[derive(Deserialize)]
struct ManifestFile {
    path: String,
    data: String, // base64
}

#[derive(Deserialize)]
struct UploadManifest {
    device_id: String,
    files: Vec<ManifestFile>,
}

async fn upload_manifest(Json(payload): Json<UploadManifest>) -> Result<String, StatusCode> {
    // On se connecte à MinIO
    let s3 = connect_s3(
        "http://127.0.0.1:9000",
        "admin",
        "9642!?!z1838iT2",
    ).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // On crée le bucket pour le device
    let bucket = format!("rustykey-{}", payload.device_id);
    create_bucket(&s3, &bucket)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // On parcours les fichiers du manifest et on les upload un par un
    for file in payload.files {
        // Decode base64
        let data = general_purpose::STANDARD.decode(&file.data)
            .map_err(|_| StatusCode::BAD_REQUEST)?;
        // Upload S3
        upload_file(&s3, &bucket, &file.path, &data).await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }
    Ok("Données de la clé envoyés !".to_string())
}


#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // On doit définir le fournisseur de crypto pour Rustls
    rustls::crypto::ring::default_provider().install_default()
        .map_err(|_| anyhow::anyhow!("Impossible d'instaler crypto ring"))?;
    
    let tls_config = build_mtls(
        "backend/backend.crt",
        "backend/backend.key",
        "backend/ca.crt",
    )?;
    
    let app = Router::new()
        .route("/upload", post(upload_manifest));
    
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], 8443));
        
    // On démarre le serveur
    axum_server::bind_rustls(addr, tls_config)
        .serve(app.into_make_service())
        .await
        .context("TLS server error")?;

    println!("Serveur mTLS + HTTP2 démarré sur https://{}:8443", addr.ip());

    Ok(())
}

fn serveur_cert(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let mut rd = BufReader::new(File::open(path)?);
    Ok(pem::certs(&mut rd)?.into_iter().map(CertificateDer::from).collect())
}

fn serveur_pkey(path: &str) -> Result<PrivateKeyDer<'static>> {
    // PKCS#8
    {
        let mut rd = BufReader::new(File::open(path)?);
        if let Some(pkcs8) = pem::pkcs8_private_keys(&mut rd)?.into_iter().next() {
            return Ok(PrivateKeyDer::from(PrivatePkcs8KeyDer::from(pkcs8)));
        }
    }
    // PKCS#1 (RSA)
    {
        let mut rd = BufReader::new(File::open(path)?);
        if let Some(rsa) = pem::rsa_private_keys(&mut rd)?.into_iter().next() {
            return Ok(PrivateKeyDer::from(PrivatePkcs1KeyDer::from(rsa)));
        }
    }
    // SEC1 (EC)
    {
        let mut rd = BufReader::new(File::open(path)?);
        if let Some(sec1) = pem::ec_private_keys(&mut rd)?.into_iter().next() {
            return Ok(PrivateKeyDer::from(PrivateSec1KeyDer::from(sec1)));
        }
    }
    anyhow::bail!("Pas de clé privé trouvé dans {path}");
}

fn client_ca(path: &str) -> Result<RootCertStore> {
    let mut rd = BufReader::new(File::open(path)?);
    let mut store = RootCertStore::empty();
    for der in pem::certs(&mut rd)? {
        store.add(CertificateDer::from(der))?;
    }
    Ok(store)
}

fn build_mtls(server_cert_path: &str,server_key_path: &str,client_ca_path: &str) -> Result<RustlsConfig> {
    let cert_chain = serveur_cert(server_cert_path).context("Err chargement cert serveur")?;
    let priv_key = serveur_pkey(server_key_path).context("Err chargement clé privé serveur")?;
    let client_ca = client_ca(client_ca_path).context("Err chargement CA client")?;
    
    // Pour mTLS
    let verifier = WebPkiClientVerifier::builder(Arc::new(client_ca))
        .build()
        .context("Err verifieur CA client")?;
    
    // On construit la configuration du serveur avec les certificats et le vérificateur
    let mut server_cfg = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(cert_chain, priv_key)
        .context("Err config certificats serveur")?;
    
    // On active aussi HTTP/2
    server_cfg.alpn_protocols = vec![
        b"h2".to_vec(),
        b"http/1.1".to_vec(),
    ];
        
    Ok(RustlsConfig::from_config(Arc::new(server_cfg)))
}


pub async fn connect_s3(endpoint: &str, access_key: &str, secret_key: &str,) -> Result<Client> {
    let creds = Credentials::new(access_key, secret_key, None, None, "static");
    let region = Region::new("us-east-1");
    let cfg = aws_config::from_env()
        .endpoint_url(endpoint) 
        .region(region)
        .credentials_provider(creds)
        .load()
        .await;

    Ok(Client::new(&cfg))
}

pub async fn create_bucket(client: &Client, bucket: &str) -> Result<()> {
    // On vérifie que le bucket n'existe pas déjà
    if client.head_bucket().bucket(bucket).send().await.is_ok() {
        return Ok(());
    }

    // On crée le bucket
    client
        .create_bucket()
        .bucket(bucket)
        .send()
        .await
        .context("Erreur à la création du bucket S3")?;

    // On active la versioning du bucket pour historisation
    client
        .put_bucket_versioning()
        .bucket(bucket)
        .versioning_configuration(
            aws_sdk_s3::types::VersioningConfiguration::builder()
                .status(aws_sdk_s3::types::BucketVersioningStatus::Enabled)
                .build(),
        )
        .send()
        .await
        .context("Impossible d'activer le versioning")?;

    Ok(())
}

async fn upload_file(client: &Client, bucket: &str, key: &str, data: &[u8]) -> Result<()> {
    create_bucket(client, bucket).await?;
    let body = ByteStream::from(data.to_vec());
    client
        .put_object()
        .bucket(bucket)
        .key(key)
        .body(body)
        .send()
        .await
        .with_context(|| format!("put_object {}", key))?;
    
    println!("Données envoyés dans le bucket {} !", bucket);
    Ok(())
}

pub async fn download_file<P: AsRef<Path>>(
    client: &Client,
    bucket: &str,
    key: &str,
    dest: P,
) -> Result<()> {
    let resp = client
        .get_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .with_context(|| format!("get_object {}", key))?;

    let bytes = resp
        .body
        .collect()
        .await
        .context("Err lecture fichier")?;

    tokio::fs::write(&dest, bytes.into_bytes())
        .await
        .with_context(|| format!("write {:?}", dest.as_ref()))?;
    Ok(())
}