// [dependencies]
// tokio = { version = "1", features = ["full"] }
// tokio-rustls = "0.25"
// rustls = "0.23"
// rustls-pemfile = "2"
// anyhow = "1"
// serde = { version = "1", features = ["derive"] }
// bincode = "2"

use std::io::BufReader;
use std::sync::Arc;
use std::path::Path;

use tokio::{
    fs,
    fs::File as TokioFile,
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

use tokio_rustls::TlsAcceptor;
use rustls::{
    ServerConfig, RootCertStore,
    server::WebPkiClientVerifier,
    pki_types::{CertificateDer, PrivateKeyDer},
};
use rustls_pemfile::Item;
use serde::{Serialize, Deserialize};
use bincode::{Encode, Decode};

#[derive(Debug, Serialize, Deserialize, Encode, Decode)]
enum AgentMessage {
    DeviceInserted {
        device_id: String,
        session_id: String,
        manifest: Manifest,
    },
}

#[derive(Debug, Serialize, Deserialize, Encode, Decode)]
enum BackendResponse {
    SessionAccepted { session_id: String },
    SessionRejected { reason: String },
}

#[derive(Debug, Serialize, Deserialize, Encode, Decode)]
struct Manifest {
    device_id: String,
    session_id: String,
    files: Vec<FileEntry>,
}

#[derive(Debug, Serialize, Deserialize, Encode, Decode)]
struct FileEntry {
    path: String,
    size: u64,
}

// Chargement des certificats serveur
fn load_certs(path: &str) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let file = std::fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut certs = Vec::new();
    while let Some(item) = rustls_pemfile::read_one(&mut reader)? {
        if let Item::X509Certificate(cert) = item {
            certs.push(CertificateDer::from(cert));
        }
    }
    Ok(certs)
}

fn load_key(path: &str) -> anyhow::Result<PrivateKeyDer<'static>> {
    let file = std::fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    while let Some(item) = rustls_pemfile::read_one(&mut reader)? {
        match item {
            Item::Pkcs8Key(key) => return Ok(PrivateKeyDer::Pkcs8(key)),
            Item::Pkcs1Key(key) => return Ok(PrivateKeyDer::Pkcs1(key)),
            Item::Sec1Key(key) => return Ok(PrivateKeyDer::Sec1(key)),
            _ => {}
        }
    }
    Err(anyhow::anyhow!("No private key found"))
}

fn load_ca(path: &str) -> anyhow::Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    for cert in load_certs(path)? {
        roots.add(cert).map_err(|e| anyhow::anyhow!("{:?}", e))?;
    }
    Ok(roots)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let server_certs = load_certs("backend/backend.crt")?;
    let server_key = load_key("backend/backend.key")?;
    let ca = load_ca("backend/ca.crt")?;
    let client_verifier = WebPkiClientVerifier::builder(ca.into())
        .build()
        .unwrap();

    let config = ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(server_certs, server_key)?;

    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:7878").await?;
    println!("✅ Backend RustyKey en écoute sur 7878");

    loop {
    let (tcp_stream, addr) = listener.accept().await?;
    let acceptor = acceptor.clone();
    tokio::spawn(async move {
        match acceptor.accept(tcp_stream).await {
            Ok(tls_stream) => {
                if let Err(e) = async_block_handler(tls_stream, addr).await {
                    eprintln!("❌ Erreur handler pour {addr}: {e:#}");
                }
            }
            Err(e) => eprintln!("❌ Erreur TLS: {:?}", e),
        }
    });
}

}

async fn async_block_handler(mut tls_stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>, addr: std::net::SocketAddr) -> anyhow::Result<()> {
    println!("🔐 Connexion TLS de {:?}", addr);

    let mut len_buf = [0u8; 4];
    tls_stream.read_exact(&mut len_buf).await?;
    let msg_len = u32::from_be_bytes(len_buf) as usize;

    let mut buf = vec![0u8; msg_len];
    tls_stream.read_exact(&mut buf).await?;

    let (message, _): (AgentMessage, _) =
        bincode::decode_from_slice(&buf, bincode::config::standard())?;

    println!("📨 Message reçu: {:?}", message);

    let AgentMessage::DeviceInserted { device_id, session_id, manifest } = message;
    let base = format!("usb_sessions/{}/{}", device_id, session_id);
    fs::create_dir_all(&base).await?;

    // Réponse d'acceptation
    let resp = BackendResponse::SessionAccepted { session_id: session_id.clone() };
    let resp_bytes = bincode::encode_to_vec(&resp, bincode::config::standard())?;
    let len = (resp_bytes.len() as u32).to_be_bytes();
    tls_stream.write_all(&len).await?;
    tls_stream.write_all(&resp_bytes).await?;

    for file_entry in &manifest.files {
        let dest_path = std::path::Path::new(&base).join(&file_entry.path);
        if let Some(parent) = dest_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        let mut out = TokioFile::create(&dest_path).await?;
        let mut remaining = file_entry.size;
        let mut buf = [0u8; 8192];
        while remaining > 0 {
            let read = tls_stream.read(&mut buf).await?;
            if read == 0 { break; }
            let to_write = std::cmp::min(read as u64, remaining) as usize;
            out.write_all(&buf[..to_write]).await?;
            remaining -= to_write as u64;
        }
        println!("✅ Fichier reçu: {}", file_entry.path);
        
        println!("🎉 Session terminée !");
    }

    Ok(())
}
