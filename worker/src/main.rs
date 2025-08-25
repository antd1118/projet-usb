use std::path::PathBuf;
use std::fs::{create_dir_all, remove_dir_all};
use std::process::Command;
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::sched::{unshare, CloneFlags};
use nix::unistd::{chdir, pivot_root, fork, ForkResult};
use caps::{CapSet, clear};
use anyhow::{Context, Result};
use clap::Parser;
use shared::{WorkerRequest, WorkerResponse, FileRequest, FileResponse, FileEntry};
use tokio::io::{AsyncBufReadExt, BufReader, AsyncWriteExt};
use serde_json;

// Arguments recus par l'agent
#[derive(Parser)]
#[command(name = "rustykey-worker")]
struct Args {
    #[arg(long)]
    request: String, // Requête JSON que l'agent nous envoie
}

struct MountInfo {
    mount_path: PathBuf,
    device_id: String,
}

#[tokio::main]
async fn main() -> Result<()> {

    let args = Args::parse();
    
    // On convertit en notre enum
    let request: WorkerRequest = serde_json::from_str(&args.request)
        .context("Erreur parsing requête JSON")?;

    match request {
        WorkerRequest::MountDevice { device_path, device_id } => {

            match secure_setup(&device_path).await {
                Ok((mount_path, fs_type)) => {

                    // besoin de réutiliser mount_path dans le namespace
                    let mount_info = MountInfo {
                        mount_path: mount_path.clone(),
                        device_id: device_id.clone(),
                    };                    
                    // On renvoi un message de succes
                    let response = WorkerResponse::MountSuccess {
                        device_id,
                        mount_path,
                        filesystem_type: fs_type,
                    };
                    
                    println!("{}", serde_json::to_string(&response)?);
                    
                    // On reste en écoute pour répondre aux reqêtes s3
                    listen_file_requests(mount_info).await?;
                }
                Err(e) => {
                    let response = WorkerResponse::MountError {
                        device_id,
                        error: e.to_string(),
                    };
                    println!("{}", serde_json::to_string(&response)?);
                }
            }
        }
        WorkerRequest::UnmountDevice { device_id } => {
            // Todo
            let response = WorkerResponse::UnmountSuccess { device_id };
            println!("{}", serde_json::to_string(&response)?);
        }
    };

    Ok(())
}

// Namespace et monte dans pivot_root
async fn secure_setup(device_path: &PathBuf) -> Result<(PathBuf, String)> {
    // Necessaire pour le montage
    let fs_type = detect_filesystem_type(device_path)?;
    
    create_namespace()?;
    
    // On crée un second fork aprés création du namespace PID pour que le processus devienne PID 1 dedans
    match unsafe { fork()? } {
        ForkResult::Parent { .. } => {
            std::process::exit(0);
        }
        ForkResult::Child => {
            // Maintenant PID 1 dans le namespace
            let mount_path = do_pivot_root(device_path, &fs_type)?;
            
            // Plus besoin de cap_sys_admin apres le montage
            drop_caps()?;
            
            return Ok((mount_path, fs_type));
        }
    }
}

// Ecoute les requêtes de STDIN
async fn listen_file_requests(mount_info: MountInfo) -> Result<()> {
    // On lit ligne par ligne les requêtes recues de l'agents par stdin
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut line = String::new();
    
    loop {
        line.clear(); // Vide la ligne précédente
        
        match reader.read_line(&mut line).await {
            Ok(0) => break, // Plus rien à lire, l'agent s'est fermé
            Ok(_) => {
                let line = line.trim(); // Enleve les espaces
                if line.is_empty() {
                    continue; // Ignore les lignes vides
                }
                
                // On convertit la ligne JSON en requête
                match serde_json::from_str::<FileRequest>(line) {
                    Ok(request) => {

                        // Traitement
                        let response = handle_file_request(request, &mount_info).await;
                        
                        // Envoie reponse stdout
                        match serde_json::to_string(&response) {
                            Ok(response_json) => {
                                println!("{}", response_json);
                                tokio::io::stdout().flush().await.ok();
                            }
                            Err(_) => {
                                // Erreur de sérialisation
                                let error_response = FileResponse::Error {
                                    message: "La requête JSON est invalide".to_string()
                                };
                                println!("{}", serde_json::to_string(&error_response).unwrap_or_default());
                            }
                        }
                    }
                    Err(_) => {
                        let error_response = FileResponse::Error {
                            message: "La requête JSON est invalide".to_string()
                        };
                        println!("{}", serde_json::to_string(&error_response).unwrap_or_default());
                    }
                }
            }
            Err(_) => break, 
        }
    }
    
    Ok(())
}

// Traite les requetes S3
async fn handle_file_request(request: FileRequest, mount_info: &MountInfo) -> FileResponse {
    match request {
        FileRequest::ListFiles { path } => list_files_in_directory(&mount_info.mount_path, &path).await,
        FileRequest::ReadFile { path } => read_file_content(&mount_info.mount_path, &path).await,
        FileRequest::WriteFile { path, data } => write_file_content(&mount_info.mount_path, &path, data).await,
        FileRequest::DeleteFile { path } => delete_file_or_directory(&mount_info.mount_path, &path).await,
        FileRequest::CreateDirectory { path } => create_directory(&mount_info.mount_path, &path).await,
        FileRequest::GetMetadata { path } => get_file_info(&mount_info.mount_path, &path).await,
    }
}

async fn list_files_in_directory(mount_path: &PathBuf, relative_path: &str) -> FileResponse {
    // On construit le chemin du dossier que l'on veut lister
    let full_path = if relative_path.is_empty() {
        mount_path.clone() // racine
    } else {
        mount_path.join(relative_path.trim_start_matches('/')) // sous dossiers
    };
        
    // On lit le contenu du dossier
    match tokio::fs::read_dir(&full_path).await {
        Ok(mut entries) => {
            let mut files = Vec::new(); // Pour contenir les fichiesr listés
            let mut directories = Vec::new(); // Pour contenir les dossiers listés
            
            // On parcourt chaque élément
            while let Ok(Some(entry)) = entries.next_entry().await {
                if let Ok(metadata) = entry.metadata().await {
                    let file_name = entry.file_name().to_string_lossy().to_string();
                    
                    // On embrique le résultat dans notre struct
                    let file_entry = FileEntry {
                        path: file_name.clone(),
                        size: if metadata.is_dir() { 0 } else { metadata.len() }, // Dossiers = taille 0
                        is_directory: metadata.is_dir(),
                        modified: metadata.modified().ok()
                            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                            .and_then(|d| chrono::DateTime::from_timestamp(d.as_secs() as i64, 0))
                            .map(|dt| dt.to_rfc3339()),
                        etag: String::new(), // todo etag
                    };
                    
                    if metadata.is_dir() {
                        directories.push(file_entry);
                    } else {
                        files.push(file_entry);
                    }
                }
            }
            
            // Trie ordre alphabétique
            directories.sort_by(|a, b| a.path.to_lowercase().cmp(&b.path.to_lowercase()));
            files.sort_by(|a, b| a.path.to_lowercase().cmp(&b.path.to_lowercase()));
            
            // dossiers puis fichiers
            let mut all_entries = directories;
            all_entries.extend(files);
                        
            // Met dans la struct de réponse
            FileResponse::FileList { files: all_entries }
        }
        Err(e) => {
            eprintln!("❌ Erreur lecture dossier {}: {}", full_path.display(), e);
            FileResponse::Error { 
                message: format!("Impossible de lister les fichiers: {}", e) 
            }
        }
    }
}

async fn read_file_content(mount_path: &PathBuf, relative_path: &str) -> FileResponse {
    let full_path = mount_path.join(relative_path.trim_start_matches('/'));
    
    match tokio::fs::read(&full_path).await {
        Ok(data) => FileResponse::FileData { data },
        Err(e) => FileResponse::Error { 
            message: format!("Impossible de lire le fichier: {}", e) 
        }
    }
}

async fn write_file_content(mount_path: &PathBuf, relative_path: &str, data: Vec<u8>) -> FileResponse {
    let full_path = mount_path.join(relative_path.trim_start_matches('/'));
    
    // On vérifie si il manque pas des dossiers parents qui ont été créés par l'utilisateur
    if let Some(parent) = full_path.parent() {
        if let Err(e) = tokio::fs::create_dir_all(parent).await {
            return FileResponse::Error { 
                message: format!("Impossible de créer les dossiers parents: {}", e) 
            };
        }
    }
    
    match tokio::fs::write(&full_path, data).await {
        Ok(_) => {
            FileResponse::Success
        }
        Err(e) => {
            eprintln!("❌ Erreur écriture fichier {}: {}", full_path.display(), e);
            FileResponse::Error { 
                message: format!("Impossible d'écrire le fichier: {}", e) 
            }
        }
    }
}

async fn delete_file_or_directory(mount_path: &PathBuf, relative_path: &str) -> FileResponse {
    let full_path = mount_path.join(relative_path.trim_start_matches('/'));
    
    // On vérifie d'abord si il existe
    match tokio::fs::metadata(&full_path).await {
        Ok(metadata) => {

            let result = if metadata.is_dir() { //Si dossier, supprime le dossier
                tokio::fs::remove_dir_all(&full_path).await
            } else {
                tokio::fs::remove_file(&full_path).await
            };
            
            match result {
                Ok(_) => FileResponse::Success,
                Err(e) => FileResponse::Error { 
                    message: format!("Impossible de supprimer: {}", e) 
                }
            }
        }
        Err(e) => {
            FileResponse::Error { 
                message: format!("Fichier non trouvé: {}", e) 
            }
        }
    }
}

async fn create_directory(mount_path: &PathBuf, relative_path: &str) -> FileResponse {
    let full_path = mount_path.join(relative_path.trim_start_matches('/'));
    
    match tokio::fs::create_dir_all(&full_path).await {
        Ok(_) => FileResponse::Success,
        Err(e) => FileResponse::Error { 
            message: format!("Impossible de créer le dossier: {}", e) 
        }
    }
}

async fn get_file_info(mount_path: &PathBuf, relative_path: &str) -> FileResponse {
    let full_path = mount_path.join(relative_path.trim_start_matches('/'));
    
    match tokio::fs::metadata(&full_path).await {
        Ok(metadata) => {
            let entry = FileEntry {
                path: relative_path.to_string(),
                size: metadata.len(),
                is_directory: metadata.is_dir(),
                modified: metadata.modified().ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .and_then(|d| chrono::DateTime::from_timestamp(d.as_secs() as i64, 0))
                    .map(|dt| dt.to_rfc3339()),
                etag: String::new(), 
            };
            FileResponse::Metadata { entry }
        }
        Err(e) => {
            FileResponse::Error { 
                message: format!("Impossible d'obtenir les infos du fichier: {}", e) 
            }
        }
    }
}


fn detect_filesystem_type(device_path: &PathBuf) -> Result<String> {
    let output = Command::new("lsblk")
        .args(&["-no", "FSTYPE"])
        .arg(device_path)
        .output()
        .context("Impossible d'exécuter lsblk")?;

    if !output.status.success() {
        return Err(anyhow::anyhow!("lsblk a échoué"));
    }

    let fs_type = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if fs_type.is_empty() {
        return Err(anyhow::anyhow!("Impossible de détecter le type de système de fichiers"));
    }
    
    Ok(fs_type)
}

fn create_namespace() -> Result<()> {
    // On met les namespace pour isoler un maximum. Pas de NEWUSER car elle ne permet pas de monter un block device. On reste sous usb-agent avec cap_sys_admin
    //todo: NEWNET
    let flags = CloneFlags::CLONE_NEWNS |
        CloneFlags::CLONE_NEWPID |
        CloneFlags::CLONE_NEWUTS |
        CloneFlags::CLONE_NEWIPC |
        CloneFlags::CLONE_NEWNET;

    unshare(flags).context("Erreur namespace")?;

    // On le rend privé (similaire à mount --make-rprivate /) (pas de partage entre namespaces)
    mount(
        Some("none"),
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE, // MS_PRIVATE pour privé / MS_REC pour récursif
        None::<&str>,
    ).context("Erreur montage privé")?;

    Ok(())
}

fn do_pivot_root(device_path: &PathBuf, fs_type: &str) -> Result<PathBuf> {
    // Préparation du pivot_root
    // On monte un tmpfs ou sera notre nouvelle racine
    let new_root = std::path::Path::new("/run/rustykey/newroot");
    create_dir_all(&new_root).context("Impossible de créer le nouveau dossier racine")?;
    
    // Monter un système de fichiers temporaire en mémoire
    mount(
        Some("tmpfs"),
        new_root, 
        Some("tmpfs"), 
        MsFlags::empty(),
        None::<&str>
    ).context("Impossible de monter le système temporaire")?;

    // On extrait le nom du device (sda1 par exemple)
    let device_name = device_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown");

    // On crée le fichier du device dans notre nouvelle racine
    let mount_path = PathBuf::from(format!("mnt/{}", device_name));
    let target = new_root.join(&mount_path);
    create_dir_all(&target).context("Impossible de créer le dossier de montage")?;

    // On monte le device dans la nouvelle racine
    mount(
        Some(device_path.to_str().unwrap()),
        &target,
        Some(fs_type),
        MsFlags::MS_NOSUID |     // Pas de programmes setuid
        MsFlags::MS_NODEV |      // Pas de fichiers device
        MsFlags::MS_NOEXEC |     // Pas d'exécution de programmes
        MsFlags::MS_NOATIME,     // Pas de mise à jour des temps d'accès
        None::<&str>,
    ).context("Impossible de monter le périphérique")?;

    let cert_dir = new_root.join("etc/rustykey");
    create_dir_all(&cert_dir).context("Impossible de créer le dossier des certificats")?;
    
    // on bind mount le dossier qui contient les certificats
    mount(
        Some("/etc/rustykey"),
        &cert_dir,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_RDONLY,
        None::<&str>,
    ).context("Impossible de monter les certificats")?;

    // On crée un dossier pour contenir l'ancienne racine pour le pivot_root
    let old_root = new_root.join(".oldroot");
    create_dir_all(&old_root).context("Impossible de créer le dossier de l'ancienne racine")?;

    // pivot_root : on change la racine et met l'ancienne dans .oldroot
    chdir(new_root).context("Impossible de changer vers la nouvelle racine")?;
    pivot_root(".", ".oldroot").context("Impossible de changer la racine")?;
    chdir("/").context("Impossible de revenir à la racine")?;

    // Créer et monter /proc dans le nouveau root (isolé PID)
    create_dir_all("/proc").context("Impossible de créer /proc")?;
    mount(
        Some("proc"),
        "/proc",
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        None::<&str>,
    ).context("Impossible de monter /proc")?;

    // On nettoie l'ancienne racine
    let _ = umount2("/.oldroot", MntFlags::MNT_DETACH);
    let _ = remove_dir_all("/.oldroot");

    Ok(mount_path)
}

fn drop_caps() -> Result<()> {
    // On supprime tout, même ambiant
    for capability_set in [CapSet::Ambient, CapSet::Effective, CapSet::Permitted, CapSet::Inheritable] {
        if let Err(e) = clear(None, capability_set) {
            eprintln!("Attention: impossible de supprimer les permissions {:?}: {}", capability_set, e);
        }
    }
    Ok(())
}