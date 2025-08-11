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
    extract::{State, Path as AxumPath}, 
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
use serde_json::Value;
use tokio::sync::mpsc;
use aws_sdk_s3::types::{NotificationConfiguration, QueueConfiguration, Event};
use tokio::process::Command;
use urlencoding::decode;

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

// 
#[derive(Debug, Clone)]
struct SimpleEvent {
    device_id: String,
    action: String,
    file_name: String,
    file_data: Vec<u8>,
}

async fn upload_manifest(Json(payload): Json<UploadManifest>) -> Result<String, StatusCode> {
    // On se connecte à MinIO
    let s3 = connect_s3(
        "http://127.0.0.1:9000",
        "admin",
        "password",
    ).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // On crée le bucket pour le device
    let bucket = format!("rustykey-{}", payload.device_id);
    create_bucket(&s3, &bucket)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // On configure le webhook pour recevoir les notifications S3
    config_webhook(&s3, &bucket)
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
    
    let s3_client = connect_s3(
        "http://127.0.0.1:9000",
        "admin",
        "password",
    ).await?;

    let tls_config = build_mtls(
        "backend/backend.crt",
        "backend/backend.key",
        "backend/ca.crt",
    )?;
    
     // On crée un channel pour gérer un évènement S3 (création, suppression) de manière asynchrone
    let (sender, receiver) = mpsc::unbounded_channel::<SimpleEvent>();

    tokio::spawn(async move {
        process_events(receiver).await;
    });

    //let webhook_token = std::env::var("RUSTYKEY_WEBHOOK_TOKEN").ok().map(Arc::new);
    
    let app = Router::new()
        .route("/upload", post(upload_manifest))
        .route("/webhook", post(webhook_handler).with_state((sender, s3_client))); // Route pour le webhook S3
    
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], 8443));

    println!("Serveur mTLS + HTTP2 démarré sur https://{}:8443", addr.ip());   
    
    let server = axum_server::bind_rustls(addr, tls_config)
        .serve(app.into_make_service());

    server.await.context("TLS server error")?;
    
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
        .metadata("rustykey-source", "internal")
        .metadata("rustykey-upload-time", &chrono::Utc::now().to_rfc3339())
        .send()
        .await
        .with_context(|| format!("put_object {}", key))?;
    
    println!("Données envoyés dans le bucket {} !", bucket);
    Ok(())
}

async fn download_file(
    client: &Client, 
    bucket: &str, 
    key: &str
) -> anyhow::Result<Option<Vec<u8>>> {
    // D'abord, on récupère les métadonnées de l'objet
    let head_resp = client
        .head_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .context("Err lecture métadonnées S3")?;

    // On vérifie si c'est un upload interne
    if let Some(metadata) = head_resp.metadata() {
        if let Some(source) = metadata.get("rustykey-source") {
            if source == "internal" {
                println!("🚫 Fichier {} ignoré (upload interne)", key);
                return Ok(None); // On ne télécharge pas
            }
        }
    }

    // Si ce n'est pas un upload interne, on télécharge
    let resp = client
        .get_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .context("Err lecture fichier S3")?;

    let bytes = resp
        .body
        .collect()
        .await
        .context("Err lecture fichier")?;

    Ok(Some(bytes.into_bytes().to_vec()))
}

// Handler minimal pour webhook
async fn webhook_handler(
    State((sender, s3_client)): State<(mpsc::UnboundedSender<SimpleEvent>, Client)>,
    Json(data): Json<Value>,
) -> Json<Value> {
    
    // Parse super basique du JSON MinIO
    if let Some(records) = data.get("Records").and_then(|r| r.as_array()) {
        for record in records {
            let event_name = record.get("eventName").and_then(|e| e.as_str()).unwrap_or("unknown");

            let bucket_name = record
                .get("s3")
                .and_then(|s3| s3.get("bucket"))
                .and_then(|bucket| bucket.get("name"))
                .and_then(|name| name.as_str())
                .unwrap_or("unknown");
            let device_id = bucket_name
                .strip_prefix("rustykey-")
                .unwrap_or("unknown")
                .to_string();
            let file_name_encoded = record
                .get("s3")
                .and_then(|s3| s3.get("object"))
                .and_then(|obj| obj.get("key"))
                .and_then(|key| key.as_str())
                .unwrap_or("unknown");
            
            let file_name = decode_file_name(file_name_encoded);
            println!("🔔 {} - {}", event_name, file_name);
            
            // Télécharge le fichier depuis S3 si c'est un ajout
            let file_data = if event_name.contains("Created") {
                match download_file(&s3_client, bucket_name, &file_name).await {
                    Ok(Some(data)) => {
                        println!("📥 Fichier externe téléchargé: {} bytes", data.len());
                        data
                    },
                    Ok(None) => {
                        println!("⏭️  Fichier interne ignoré: {}", file_name);
                        continue; // On passe au suivant sans créer d'événement
                    },
                    Err(e) => {
                        println!("❌ Erreur téléchargement {}: {}", file_name, e);
                        Vec::new()
                    }
                }
            } else {
                Vec::new()
            };
            
            let event = SimpleEvent {
                device_id: device_id.clone(),
                action: event_name.to_string(),
                file_name: file_name.to_string(),
                file_data,
            };
            
            // Envoie l'événement via le channel
            let _ = sender.send(event);
        }
    }
    Json(json!({"status": "ok"}))
}

// Fonction pour traiter les événements
async fn process_events(mut receiver: mpsc::UnboundedReceiver<SimpleEvent>) {
    while let Some(event) = receiver.recv().await {
        println!("⚡ Traitement: {} -> {} ({} bytes)", 
            event.device_id, event.file_name, event.file_data.len());
        
        // Tes traitements ici...
        if event.action.contains("Created") {
            println!("  ✅ Fichier ajouté avec {} bytes de données", event.file_data.len());
            // Ici tu peux utiliser event.file_data pour envoyer à l'agent
        } else if event.action.contains("Removed") {
            println!("  🗑️ Fichier supprimé");
        }
    }
}

// Active les événements webhook pour le bucket (pour recevoir les données du bucket)
pub async fn config_webhook(client: &Client, bucket: &str) -> Result<()> {
    //  On crée une ARN minio pour le webhook rustykey.
    let queue_arn = format!("arn:minio:sqs::rustykey:webhook");

    // On déclare les événements qui nous intéressent sur ce bucket
    let qcfg = QueueConfiguration::builder()
        .queue_arn(queue_arn)
        .events(Event::S3ObjectCreatedPut)
        .events(Event::S3ObjectCreatedCompleteMultipartUpload)
        .events(Event::S3ObjectRemovedDelete)
        .build()
        .map_err(|e| anyhow::anyhow!("Erreur création QueueConfiguration: {}", e))?;

    // Configure la notification pour le bucket
    let notif = NotificationConfiguration::builder()
        .queue_configurations(qcfg)
        .build();

    // On l'applique au bucket
    client
        .put_bucket_notification_configuration()
        .bucket(bucket)
        .notification_configuration(notif)
        .send()
        .await
        .with_context(|| format!("Configurer webhook pour bucket {bucket}"))?;

    println!("🔔 Webhook activé sur {bucket}");
    Ok(())
}

fn decode_file_name(encoded_name: &str) -> String {
    decode(encoded_name)
        .map(|s| s.to_string())
        .unwrap_or_else(|_| encoded_name.to_string())
}