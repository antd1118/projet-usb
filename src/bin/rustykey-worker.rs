use std::process::{Command};
use std::path::{Path, PathBuf};
use nix::sched::{unshare, CloneFlags};
use nix::mount::{mount, umount2, MsFlags, MntFlags};
use nix::unistd::{fork, ForkResult, pivot_root, chdir};
use std::fs::{self, create_dir_all, remove_dir_all, File};
use serde::{Deserialize, Serialize};
use std::io::{BufReader, BufRead};
use caps::{CapSet, clear};
use libc::{prctl, PR_SET_NO_NEW_PRIVS};
use std::sync::Arc;
use tokio_rustls::TlsConnector;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use rustls::{ClientConfig, RootCertStore, pki_types::{CertificateDer, PrivateKeyDer, ServerName}};
use bincode::{Encode, Decode};
use std::env;
use tokio::time::timeout;
use std::time::Duration;
use anyhow::{Result, Context};
use walkdir::WalkDir;
fn main() {
    if let Err(e) = run_worker() {
        eprintln!("❌ rustykey-worker: {e:#}");
        std::process::exit(1);
    }
}

fn run_worker() -> Result<()> {

    let device_path = env::args().nth(1)
        .ok_or_else(|| anyhow::anyhow!("❌ Aucun chemin de périphérique fourni"))?;
    if !Path::new(&device_path).exists() {
        return Err(anyhow::anyhow!("❌ Le périphérique {} n'existe pas", device_path));
    }

    create_namespace()?;
    
    // On crée un second fork aprés création du namespace pour que le processus devienne PID 1 dedans
    match unsafe { fork()? } {
        ForkResult::Parent { .. } => {
            std::process::exit(0);
        }
        ForkResult::Child => {
            // Maintenant PID 1 dans le namespace
            // On fait la suite des opérations (montage et envoi des fichiers)
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let fs_type = get_fs_type(&device_path)?;
                let mount_path = do_pivot_root(&device_path, fs_type)?;
                drop_cap()?;
                send_files(mount_path).await
            })?;
        }
    }
    Ok(())
}

fn create_namespace() -> Result<()> {
    // On met les namespace pour isoler un maximum. Pas de NEWUSER car elle ne permet pas de monter un block device. On reste sous usb-agent avec cap_sys_admin
    //todo: NEWNET
    let flags = CloneFlags::CLONE_NEWNS |
        CloneFlags::CLONE_NEWPID |
        CloneFlags::CLONE_NEWUTS |
        CloneFlags::CLONE_NEWIPC;

    unshare(flags).context("❌ unshare échoué")?;

    // On le rend privé (similaire à mount --make-rprivate /) (pas de partage entre namespaces)
    mount(
        Some("none"),
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE, // MS_PRIVATE pour privé / MS_REC pour récursif
        None::<&str>,
    ).context("❌ mount --make-rprivate échoué")?;

    Ok(())
}

fn do_pivot_root(device_path: &str, fs_type: String) -> Result<PathBuf> {
    // Préparation du pivot_root
    // On monte un tmpfs ou sera notre nouvelle racine
    let new_root = Path::new("/run/rustykey/newroot");
    create_dir_all(&new_root)?;
    mount(
        Some("tmpfs"),
        new_root, 
        Some("tmpfs"), 
        MsFlags::empty(),
        None::<&str>
    ).context("❌ tmpfs mount échoué")?;

    // On extrait le nom du device
    let device_name = Path::new(device_path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("unk")
        .to_string();

    // On crée le fichier du device dans notre nouvelle racine
    let mount_path = PathBuf::from(format!("mnt/{}", device_name));
    let bind_target = new_root.join(&mount_path);
    create_dir_all(&bind_target)?;

    // On monte le device dans la nouvelle racine
    mount(
        Some(device_path),
        &bind_target,
        Some(fs_type.as_str()),
        MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC | MsFlags::MS_NOATIME, // flags pour sécurité max
        None::<&str>,
    ).context("❌ Mount device échoué")?;

    // on bind mount le dossier qui contient les certificats
    create_dir_all("/run/rustykey/newroot/etc/rustykey")?;
    mount(
        Some("/etc/rustykey"),
        "/run/rustykey/newroot/etc/rustykey",
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC | MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC | MsFlags::MS_NOATIME,
        None::<&str>,
    ).context("❌ Bind mount échoué")?;

    // On crée un dossier pour contenir l'ancienne racine pour le pivot_root
    let old_root = new_root.join(".oldroot");
    create_dir_all(&old_root)?;

    // pivot_root : on change la racine et met l'ancienne dans .oldroot
    chdir(new_root)?;
    pivot_root(".", ".oldroot").expect("❌ pivot_root échoué");
    chdir("/")?;

    // Créer et monter /proc dans le nouveau root (isolé PID)
    create_dir_all("/proc")?;
    mount(
        Some("proc"),
        "/proc",
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        None::<&str>,
    ).context("❌ mount proc échoué")?;

    // On nettoie l'ancienne racine
    umount2("/.oldroot", MntFlags::MNT_DETACH).ok();
    remove_dir_all("/.oldroot").ok();

    Ok(mount_path)
}

fn get_fs_type(device_path: &str) -> Result<String> {
    let output = Command::new("lsblk")
        .args(&["-no", "FSTYPE", device_path])
        .output()?;
    if !output.status.success() {
        return Err(anyhow::anyhow!("lsblk a échoué sur {}", device_path));
    }
    let fs_type = String::from_utf8_lossy(&output.stdout).trim().to_string();

    if fs_type.is_empty() {
        Err(anyhow::anyhow!("Impossible de détecter le type de FS de {}", device_path))
    } else {
        Ok(fs_type)
    }
}

fn drop_cap() -> Result<()> {

    // 1) Tout vider, y compris l’Ambient
    for set in [CapSet::Ambient, CapSet::Effective, CapSet::Permitted, CapSet::Inheritable] {
        if let Err(e) = clear(None, set) {
            eprintln!("Warn: clear {:?} -> {}", set, e);
        }
    }

    // 2) Verrouiller toute élévation future (setuid / file caps)
    let ret = unsafe { prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret != 0 {
        return Err(anyhow::anyhow!("Failed PR_SET_NO_NEW_PRIVS: {}", std::io::Error::last_os_error()));
    }
    
    Ok(())
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

#[derive(Debug, Serialize, Deserialize, Encode, Decode)]
enum AgentMessage {
    DeviceInserted {
        device_id: String,
        session_id: String,
        manifest: Manifest,
    },
    // autres messages éventuels
}

#[derive(Debug, Serialize, Deserialize, Encode, Decode)]
enum BackendResponse {
    SessionAccepted { session_id: String },
    SessionRejected { reason: String },
    // autres variantes...
}

fn load_ca_certs(filename: &str) -> anyhow::Result<RootCertStore> {
    let mut root_store = RootCertStore::empty();
    let file = File::open(filename)?;
    let mut reader = BufReader::new(file);
    while let Some(item) = rustls_pemfile::read_one(&mut reader)? {
        if let rustls_pemfile::Item::X509Certificate(cert) = item {
            root_store.add(cert).map_err(|e| anyhow::anyhow!("{:?}", e))?;
        }
    }
    Ok(root_store)
}

fn load_client_cert(filename: &str) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let file = File::open(filename)?;
    let mut reader = BufReader::new(file);
    let mut certs = Vec::new();
    while let Some(item) = rustls_pemfile::read_one(&mut reader)? {
        if let rustls_pemfile::Item::X509Certificate(cert) = item {
            certs.push(CertificateDer::from(cert));
        }
    }
    Ok(certs)
}

fn load_client_key(filename: &str) -> anyhow::Result<PrivateKeyDer<'static>> {
    use rustls_pemfile::Item;
    let file = File::open(filename)?;
    let mut reader = BufReader::new(file);
    while let Some(item) = rustls_pemfile::read_one(&mut reader)? {
        match item {
            Item::Pkcs8Key(key) => return Ok(PrivateKeyDer::Pkcs8(key)),
            Item::Pkcs1Key(key) => return Ok(PrivateKeyDer::Pkcs1(key)),
            Item::Sec1Key(key)  => return Ok(PrivateKeyDer::Sec1(key)),
            _ => {}
        }
    }
    Err(anyhow::anyhow!("No private key found"))
}

async fn send_files(folder: PathBuf) -> anyhow::Result<()> {
    // === TLS Config ===
    let ca_store = load_ca_certs("/etc/rustykey/ca.crt")?;
    let certs = load_client_cert("/etc/rustykey/agent.crt")?;
    let key = load_client_key("/etc/rustykey/agent.key")?;

    let server_name = ServerName::try_from("rustykey-backend.local").unwrap();
    let config = ClientConfig::builder()
        .with_root_certificates(ca_store)
        .with_client_auth_cert(certs, key)?;
    let connector = TlsConnector::from(Arc::new(config));

    println!("🔗 Tentative de connexion TCP...");
    let stream = timeout(
        Duration::from_secs(5),
        tokio::net::TcpStream::connect("127.0.0.1:7878")
    )
    .await
    .map_err(|_| anyhow::anyhow!("⏱️ Timeout TCP (backend injoignable)"))??;
    let mut tls = connector.connect(server_name, stream).await?;
    println!("✅ Connexion TLS OK");

    // === Explore tous les fichiers récursivement ===
    let mut files_to_send = Vec::new();
    for entry in WalkDir::new(&folder)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let rel_path = entry.path().strip_prefix(&folder).unwrap().to_string_lossy().to_string();
        let size = entry.metadata()?.len();
        files_to_send.push((rel_path, entry.path().to_owned(), size));
    }

    // === Prépare le manifest ===
    let files: Vec<FileEntry> = files_to_send.iter()
        .map(|(rel_path, _, size)| FileEntry {
            path: rel_path.clone(),
            size: *size,
        })
        .collect();

    let manifest = Manifest {
        device_id: "my-usb".to_string(),
        session_id: "sess-42".to_string(),
        files,
    };

    let message = AgentMessage::DeviceInserted {
        device_id: manifest.device_id.clone(),
        session_id: manifest.session_id.clone(),
        manifest,
    };
    let serialized = bincode::encode_to_vec(&message, bincode::config::standard())?;
    let len = (serialized.len() as u32).to_be_bytes();

    tls.write_all(&len).await?;
    tls.write_all(&serialized).await?;

    // === Lecture de la réponse Backend ===
    let mut resp_len_buf = [0u8; 4];
    tls.read_exact(&mut resp_len_buf).await?;
    let resp_len = u32::from_be_bytes(resp_len_buf) as usize;
    let mut resp_buf = vec![0u8; resp_len];
    tls.read_exact(&mut resp_buf).await?;
    let (response, _): (BackendResponse, _) = bincode::decode_from_slice(&resp_buf, bincode::config::standard())?;
    println!("Backend response: {:?}", response);

    // === Stream chaque fichier, dans l’ordre ===
    for (rel_path, abs_path, size) in &files_to_send {
        println!("➡️ Envoi fichier: {} ({} bytes)", rel_path, size);
        let mut file = tokio::fs::File::open(abs_path).await?;
        let mut remaining = *size;
        let mut buf = [0u8; 8192];
        while remaining > 0 {
            let n = file.read(&mut buf).await?;
            if n == 0 { break; }
            tls.write_all(&buf[..n]).await?;
            remaining -= n as u64;
        }
        println!("✅ Fichier envoyé: {}", rel_path);
    }
    println!("🎉 Tous les fichiers envoyés !");
    Ok(())
}

