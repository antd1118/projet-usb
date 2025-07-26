use serde::{Deserialize, Serialize};
use tokio::fs::{self, File};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
#[derive(Debug, Deserialize, Serialize)]
struct Manifeste {
    device_id: String,
    session_id: String,
    files: Vec<FileEntry>,
}

#[derive(Debug, Deserialize, Serialize)]
struct FileEntry {
    path: String,
    size: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let listener = TcpListener::bind("0.0.0.0:7878").await?;
    println!("🚦 Backend RustyKey écoute sur le port 7878...");

    loop {
        let (mut socket, addr) = listener.accept().await?;
        println!("🔗 Connexion entrante depuis {:?}", addr);

        tokio::spawn(async move {
            // 1. Lire le manifeste JSON envoyé par l’agent
            let mut len_buf = [0u8; 4];
            socket.read_exact(&mut len_buf).await.unwrap();
            let json_len = u32::from_be_bytes(len_buf) as usize;

            // 2) lire exactement json_len octets
            let mut json_buf = vec![0u8; json_len];
            socket.read_exact(&mut json_buf).await.unwrap();

            let manifeste: Manifeste = match serde_json::from_slice(&json_buf) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("❌ Erreur de parsing manifeste: {}", e);
                    return;
                }
            };
            println!("📦 Manifeste reçu: {:#?}", manifeste);



            // 2. Créer dossier session/device
            let base = format!("usb_sessions/{}/{}", manifeste.device_id, manifeste.session_id);
            fs::create_dir_all(&base).await.unwrap();

            // 3. Recevoir chaque fichier envoyé par l’agent
            for file in &manifeste.files {
                let file_path = format!("{}/{}", base, file.path);

                if let Some(parent) = std::path::Path::new(&file_path).parent() {
                    fs::create_dir_all(parent).await.unwrap();
                }
                let mut f = File::create(&file_path).await.unwrap();
                let mut remaining = file.size;
                let mut buffer = vec![0u8; 8192];
                while remaining > 0 {
                    let read = socket.read(&mut buffer).await.unwrap();
                    if read == 0 { break; }
                    f.write_all(&buffer[..read]).await.unwrap();
                    remaining -= read as u64;
                }
                println!("✅ Fichier {} reçu ({})", file.path, file.size);
            }
            println!("🎉 Session terminée !");
        });
    }
}
