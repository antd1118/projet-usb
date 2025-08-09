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
    extract::Multipart,
    response::Json as ResponseJson,
};
use std::fs::create_dir_all;
use std::time::Duration;
use tokio::sync::broadcast;
use tokio::time::sleep;
use walkdir::WalkDir;
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

// async fn init_session(Json(payload): Json<InitSession>) -> Result<ResponseJson<SessionResponse>, StatusCode> {
//     println!("📥 Session init from USB: {:?}", payload);
    
//     let session_id = uuid::Uuid::new_v4().to_string();
//     let base_dir = format!("usb_sessions/{}/{}", payload.serial, session_id);
    
//     if let Err(_) = fs::create_dir_all(&base_dir).await {
//         return Err(StatusCode::INTERNAL_SERVER_ERROR);
//     }
    
//     let response = SessionResponse {
//         status: "accepted".to_string(),
//         session_id,
//     };
    
//     Ok(ResponseJson(response))
// }

async fn upload_manifest(
    Json(payload): Json<UploadManifest>
) -> Result<String, StatusCode> {
    // Prépare S3
    let s3 = connect_s3(
        "http://127.0.0.1:9000",
        "admin",
        "9642!?!z1838iT2",
    ).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let bucket = format!("rustykey-{}", payload.device_id);
    ensure_bucket(&s3, &bucket)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    for file in payload.files {
        // Decode base64
        let data = general_purpose::STANDARD.decode(&file.data)
            .map_err(|_| StatusCode::BAD_REQUEST)?;
        // Upload S3
        upload_file_to_s3(&s3, &bucket, &file.path, &data).await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }
    Ok("All files uploaded successfully".to_string())
}

// async fn complete_session(Json(payload): Json<InitSession>) -> Result<String, StatusCode> {
//     println!("🎉 Session terminée pour: {:?}", payload);
    
//     // Ici vous pouvez déclencher la synchronisation S3
//     // sync_to_s3(&payload.serial).await;
    
//     Ok("Session completed".to_string())
// }

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    rustls::crypto::ring::default_provider().install_default()
        .map_err(|_| anyhow::anyhow!("Failed to install crypto provider"))?;
    
    let tls_config = build_mtls_config_with_http2(
        "backend/backend.crt",
        "backend/backend.key",
        "backend/ca.crt",
    )?;
    
    let app = Router::new()
        .route("/upload", post(upload_manifest));
    
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], 8443));
    
    println!("Serveur mTLS + HTTP/2 démarré sur https://{}:8443", addr.ip());
    
    // Configuration du serveur avec support HTTP/2
    axum_server::bind_rustls(addr, tls_config)
        .serve(app.into_make_service())
        .await
        .context("TLS server error")?;

    Ok(())
    // // Notifications MinIO → broadcast
    // let (tx, _) = broadcast::channel::<MinioEvent>(32);
    // let s3_clone = s3.clone();
    // let mount_clone = mount_path.clone();

    // // 1) serveur webhook
    // tokio::spawn(start_event_server(tx.clone()));

    // // 2) consommateur des events
    // tokio::spawn(async move {
    //     let mut rx = tx.subscribe();
    //     while let Ok(evt) = rx.recv().await {
    //         if let Err(e) = handle_event(&s3_clone, evt, &mount_clone).await {
    //             eprintln!("[sync] {e}");
    //         }
    //     }
    // });

    // // keep‑alive (PID 1 dans le namespace)
    // loop {
    //     sleep(Duration::from_secs(3600)).await;
    // }
}

fn load_cert_chain(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let mut rd = BufReader::new(File::open(path)?);
    Ok(pem::certs(&mut rd)?.into_iter().map(CertificateDer::from).collect())
}

fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>> {
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
    anyhow::bail!("no private key found in {path}");
}

fn load_client_ca_store(path: &str) -> Result<RootCertStore> {
    let mut rd = BufReader::new(File::open(path)?);
    let mut store = RootCertStore::empty();
    for der in pem::certs(&mut rd)? {
        store.add(CertificateDer::from(der))?;
    }
    Ok(store)
}

fn build_mtls_config_with_http2(
    server_cert_path: &str,
    server_key_path: &str,
    client_ca_path: &str,
) -> Result<RustlsConfig> {
    let cert_chain = load_cert_chain(server_cert_path).context("load server cert chain")?;
    let priv_key = load_private_key(server_key_path).context("load server key")?;
    let client_ca = load_client_ca_store(client_ca_path).context("load client CA")?;
    
    let verifier = WebPkiClientVerifier::builder(Arc::new(client_ca))
        .build()
        .context("build client verifier")?;
    
    // Configuration ServerConfig avec ALPN pour HTTP/2
    let mut server_cfg = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(cert_chain, priv_key)
        .context("with_single_cert")?;
    
    // IMPORTANT: Configuration explicite d'ALPN pour HTTP/2
    server_cfg.alpn_protocols = vec![
        b"h2".to_vec(),      // HTTP/2
        b"http/1.1".to_vec(), // HTTP/1.1 en fallback
    ];
    
    println!("✅ ALPN configuré: h2, http/1.1");
    
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

pub async fn ensure_bucket(client: &Client, bucket: &str) -> Result<()> {
    // 1. Quick existence probe.
    if client.head_bucket().bucket(bucket).send().await.is_ok() {
        return Ok(());
    }

    // 2. Create the bucket (region is ignored by MinIO).
    client
        .create_bucket()
        .bucket(bucket)
        .send()
        .await
        .context("failed to create bucket")?;

    // 3. Enable versioning (optional but recommended).
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
        .context("failed to enable versioning")?;

    Ok(())
}

pub async fn ensure_webhook_admin_api(bucket: &str) -> Result<()> {
    // Configuration du webhook via l'API Admin MinIO
    let webhook_config = json!({
        "webhook": {
            "1": {
                "enable": true,
                "endpoint": "http://127.0.0.1:8686/events",
                "authToken": "",
                "queueDir": "",
                "queueLimit": 0
            }
        }
    });

    let client = reqwest::Client::new();
    
    // 1) Configurer le service de notification webhook
    let response = client
        .put("http://127.0.0.1:9000/minio/admin/v3/config")
        .header("Authorization", "Bearer YOUR_ADMIN_TOKEN") // À remplacer
        .header("Content-Type", "application/json")
        .body(webhook_config.to_string())
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(anyhow::anyhow!("Échec configuration webhook: {}", response.status()));
    }

    // 2) Activer les notifications sur le bucket
    let bucket_notification = json!({
        "events": ["s3:ObjectCreated:*", "s3:ObjectRemoved:*"],
        "arn": "arn:minio:sns::1:webhook"
    });

    let response = client
        .put(&format!("http://127.0.0.1:9000/{}", bucket))
        .header("Authorization", "Bearer YOUR_ADMIN_TOKEN")
        .header("Content-Type", "application/json")
        .query(&[("notification", "")])
        .body(bucket_notification.to_string())
        .send()
        .await?;

    if response.status().is_success() {
        println!("✅ Webhook configuré via API Admin");
        Ok(())
    } else {
        Err(anyhow::anyhow!("Échec configuration bucket notification: {}", response.status()))
    }
}

async fn upload_file_to_s3(client: &Client, bucket: &str, key: &str, data: &[u8]) -> Result<()> {
    ensure_bucket(client, bucket).await?;
    let body = ByteStream::from(data.to_vec());
    client
        .put_object()
        .bucket(bucket)
        .key(key)
        .body(body)
        .send()
        .await
        .with_context(|| format!("put_object {}", key))?;
    
    println!("✅ Données envoyés dans le bucket {}", bucket);
    Ok(())
}

/// Download object `key` from `bucket` to the local `dest` path.
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
        .context("stream read")?;

    tokio::fs::write(&dest, bytes.into_bytes())
        .await
        .with_context(|| format!("write {:?}", dest.as_ref()))?;
    Ok(())
}


/* -------------------------------------------------------------------------
 *  EVENT SERVER + HANDLER
 * --------------------------------------------------------------------- */


#[derive(Deserialize, Debug, Clone)]
struct MinioEvent {
    #[serde(rename = "EventName")] event_name: String,
    #[serde(rename = "Key")] key: String,
    #[serde(rename = "Bucket")] bucket: String,
}

/// Serveur webhook `POST /events` – compatible Axum 0.8 + hyper 0.14 interne.
async fn start_event_server(tx: broadcast::Sender<MinioEvent>) -> Result<()> {
    // Handler JSON → broadcast
    let handler = move |Json(evt): Json<MinioEvent>| {
        let tx = tx.clone();
        async move {
            let _ = tx.send(evt);
            axum::response::Response::builder()
                .status(204)
                .body(axum::body::Body::empty())
                .unwrap()
        }
    };

    let app = Router::new().route("/events", post(handler));

    // Utilisation d’un TcpListener explicite pour éviter l’import hyper ::Server
    let listener = TcpListener::bind("0.0.0.0:8686").await?;
    axum::serve(listener, app.into_make_service()).await?;
    Ok(())
}

/// Applique l’événement S3 localement.
async fn handle_event(client: &Client, evt: MinioEvent, usb_root: &Path) -> Result<()> {
    let local_path = usb_root.join(&evt.key);
    match evt.event_name.as_str() {
        "s3:ObjectCreated:Put" | "s3:ObjectCreated:CompleteMultipartUpload" => {
            if let Some(parent) = local_path.parent() {
                create_dir_all(parent)?;
            }
            download_file(client, &evt.bucket, &evt.key, &local_path).await?;
            println!("⬇️  Synced {}", evt.key);
        }
        "s3:ObjectRemoved:Delete" => {
            if tokio::fs::try_exists(&local_path).await? {
                tokio::fs::remove_file(&local_path).await?;
                println!("🗑️  Deleted {}", evt.key);
            }
        }
        _ => {}
    }
    Ok(())
}
