use anyhow::{Context, Result};
use caps::{CapSet, clear};
use libc::{prctl, PR_SET_NO_NEW_PRIVS};
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::sched::{unshare, CloneFlags};
use nix::unistd::{chdir, fork, ForkResult, pivot_root};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs::{self, create_dir_all, remove_dir_all};
use std::path::{Path, PathBuf};
use std::process::Command;
use walkdir::WalkDir;
use base64::{engine::general_purpose, Engine as _};
use reqwest::{ Identity, Certificate};
use reqwest::Client as HttpClient;

fn main() {
    if let Err(e) = run_worker() {
        eprintln!("ERREUR WORKER : {e:#}");
        std::process::exit(1);
    }
}

fn run_worker() -> Result<()> {

    let mut args = env::args().skip(1);        // arg[0] = binaire
    let device_path = args.next().ok_or_else(|| anyhow::anyhow!("Pas de partition"))?;
    let device_id = args.next().unwrap_or_else(|| "inconnu".into());

    if !Path::new(&device_path).exists() {
        return Err(anyhow::anyhow!("Le périphérique à {} n'existe pas", device_path));
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
                let files = build_manifest(&mount_path).await?;
                let client = build_mtls_client()?;
                send_manifest("https://127.0.0.1:8443/upload", &device_id, files, &client).await?;
                Ok::<(), anyhow::Error>(())
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

    unshare(flags).context("unshare échoué")?;

    // On le rend privé (similaire à mount --make-rprivate /) (pas de partage entre namespaces)
    mount(
        Some("none"),
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE, // MS_PRIVATE pour privé / MS_REC pour récursif
        None::<&str>,
    ).context("mount --make-rprivate échoué")?;

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
    ).context("tmpfs mount échoué")?;

    // On extrait le nom du device (sda1 par exemple)
    let device_name = Path::new(device_path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("unk")
        .to_string();

    // On crée le fichier du device dans notre nouvelle racine
    let mount_path = PathBuf::from(format!("mnt/{}", device_name));
    let target = new_root.join(&mount_path);
    create_dir_all(&target)?;

    // On monte le device dans la nouvelle racine
    mount(
        Some(device_path),
        &target,
        Some(fs_type.as_str()),
        MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC | MsFlags::MS_NOATIME, // flags pour sécurité max
        None::<&str>,
    ).context("Mount device échoué")?;

    // on bind mount le dossier qui contient les certificats
    create_dir_all("/run/rustykey/newroot/etc/rustykey")?;
    mount(
        Some("/etc/rustykey"),
        "/run/rustykey/newroot/etc/rustykey",
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC | MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC | MsFlags::MS_NOATIME,
        None::<&str>,
    ).context("Bind mount échoué")?;

    // On crée un dossier pour contenir l'ancienne racine pour le pivot_root
    let old_root = new_root.join(".oldroot");
    create_dir_all(&old_root)?;

    // pivot_root : on change la racine et met l'ancienne dans .oldroot
    chdir(new_root).context("chdir(new_root) avant pivot_root")?;
    pivot_root(".", ".oldroot").context("pivot_root('.', '.oldroot')")?;
    chdir("/").context("chdir('/') après pivot_root")?;

    // Créer et monter /proc dans le nouveau root (isolé PID)
    create_dir_all("/proc")?;
    mount(
        Some("proc"),
        "/proc",
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        None::<&str>,
    ).context("mount proc échoué")?;

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

    // On supprime les capacités Ambient, Effective, Permitted et Inheritable
    for set in [CapSet::Ambient, CapSet::Effective, CapSet::Permitted, CapSet::Inheritable] {
        if let Err(e) = clear(None, set) {
            eprintln!("Erreur clear cap {:?} : {}", set, e);
        }
    }

    // On empêche l'acquisition de nouveaux privilèges 
    let ret = unsafe { prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret != 0 {
        return Err(anyhow::anyhow!("Erreur PR_SET_NO_NEW_PRIVS: {}", std::io::Error::last_os_error()));
    }
    
    Ok(())
}

#[derive(Serialize)]
struct ManifestFile {
    path: String,
    data: String, // base64
}


async fn build_manifest(mount_path: &Path) -> Result<Vec<ManifestFile>> {
    let mut files = Vec::new();
    // On parcours tous les fichiers à partir de mount_path
    for entry in WalkDir::new(mount_path).follow_links(false).same_file_system(true).into_iter().filter_map(Result::ok) {
        if entry.file_type().is_file() {
            // Chemin relatif par rapport à mount_path
            let rel_path = entry.path().strip_prefix(mount_path)
                .unwrap_or(entry.path()) 
                .to_string_lossy()
                .to_string();
            
            // On lit le contenu du fichier et on l'encode en base64
            let contents = tokio::fs::read(entry.path()).await?;
            let encoded = general_purpose::STANDARD.encode(&contents);

            files.push(ManifestFile { path: rel_path, data: encoded });
        }
    }
    Ok(files)
}


fn build_mtls_client() -> Result<HttpClient> {
    let key = fs::read("/etc/rustykey/agent.key").context("read agent.key")?;
    let crt = fs::read("/etc/rustykey/agent.crt").context("read agent.crt")?;
    let mut id_pem = Vec::with_capacity(key.len()+crt.len()+64);
    id_pem.extend_from_slice(&key);
    id_pem.extend_from_slice(&crt);
    let identity = Identity::from_pem(&id_pem).context("identity")?;

    let ca = fs::read("/etc/rustykey/ca.crt").context("read ca.crt")?;
    let ca_cert = Certificate::from_pem(&ca).context("CA")?;

    Ok(HttpClient::builder()
        .use_rustls_tls()
        .add_root_certificate(ca_cert)
        .identity(identity)
        .resolve("rustykey-backend.local", "127.0.0.1:8443".parse().unwrap())
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("build reqwest client")?)
}



async fn send_manifest(url: &str, device_id: &str, files: Vec<ManifestFile>, client: &HttpClient) -> anyhow::Result<()> {

    let body = serde_json::json!({
        "device_id": device_id,
        "files": files
    });

    let resp = client.post(url).json(&body).send().await?;
    if !resp.status().is_success() {
        anyhow::bail!("Erreur envoie des données au backend: {}", resp.status());
    }
    Ok(())
}
