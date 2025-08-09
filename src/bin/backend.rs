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
use axum_server::tls_rustls::RustlsConfig;
use std::fs::create_dir_all;
use std::time::Duration;
use tokio::sync::broadcast;
use tokio::time::sleep;
use walkdir::WalkDir;
use serde_json::json;
use base64::{engine::general_purpose, Engine as _};
use axum_server::tls_rustls::RustlsAcceptor;
use std::fs::File;
use std::io::BufReader;

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
    
    // IMPORTANT: Initialiser le CryptoProvider avant toute autre opération TLS
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("Failed to install crypto provider"))?;

    // Méthode 2: Configuration manuelle avec CA séparé
    let config = create_tls_config_with_ca().await?;

    // Configuration de l'application Axum
    let app = Router::new()
        // .route("/init", post(init_session))
        .route("/upload", post(upload_manifest));
        // .route("/complete", post(complete_session));

    println!("✅ Backend RustyKey TLS en écoute sur 8443");

    // Serveur TLS avec axum-server
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], 8443));
    
    axum_server::bind_rustls(addr, config)
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

async fn create_tls_config_with_ca() -> anyhow::Result<RustlsConfig> {
    // Lecture du certificat serveur
    let cert_file = tokio::fs::read("backend/backend.crt").await
        .context("Failed to read server certificate")?;
    let cert_pem = String::from_utf8(cert_file)
        .context("Server certificate is not valid UTF-8")?;

    // Lecture de la clé privée
    let key_file = tokio::fs::read("backend/backend.key").await
        .context("Failed to read private key")?;
    let key_pem = String::from_utf8(key_file)
        .context("Private key is not valid UTF-8")?;

    // Lecture du certificat CA
    let ca_file = tokio::fs::read("backend/ca.crt").await
        .context("Failed to read CA certificate")?;
    let ca_pem = String::from_utf8(ca_file)
        .context("CA certificate is not valid UTF-8")?;

    // Création de la chaîne complète (serveur + CA)
    let full_chain = format!("{}\n{}", cert_pem, ca_pem);

    // Configuration avec la chaîne complète
    let config = RustlsConfig::from_pem(
        full_chain.into_bytes(),
        key_pem.into_bytes(),
    )
    .await
    .context("Failed to create TLS config from PEM data")?;

    Ok(config)
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
