use tokio_udev::{AsyncMonitorSocket, MonitorBuilder, Enumerator};
use tokio_stream::StreamExt;
use std::process::{Command};
use std::path::{Path, PathBuf};
use nix::sched::{unshare, CloneFlags};
use nix::mount::{mount, umount2, MsFlags, MntFlags};
use nix::unistd::{fork, ForkResult, pivot_root, chdir};
use std::fs::{self, create_dir_all, remove_dir_all, write, File};
use serde::{Deserialize, Serialize};
use std::io::{Write, Read, BufReader, BufRead};
use std::net::TcpStream;
use uuid::Uuid;
use walkdir::WalkDir;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    // Gerons le cas ou il y a déjà un périphérique branché et monté au démarrage de l'agent

    let mut enumerator = Enumerator::new()?;

    enumerator.match_subsystem("block")?;
    for device in enumerator.scan_devices()? {
        // On vérifie que c'est une partition USB
        let is_usb = device.property_value("ID_USB_DRIVER").is_some()
            || device.property_value("ID_BUS").map_or(false, |v| v == "usb");
        let is_part = device.property_value("DEVTYPE").map_or(false, |v| v == "partition");
        if is_usb && is_part {
            if let Some(devnode) = device.devnode() {
                let device_path = devnode.display().to_string();
                println!("🔎 Périphérique USB déjà présent : {}", device_path);
                //handle_existing_partition(&device_path)?; Je voulais le démonter DU FS principal mais pas possible car le service account n'a pas les droits (dossier /media/user propriétaire), il faudrait une cap en plus mais ca diminuerait la sécurité
                println!("Veuillez le débrancher et le rebrancher");
            }
        }
    }

    // Création du moniteur synchrone
    let monitor = MonitorBuilder::new()?
        .match_subsystem("block")?
        .listen()?;

    // Conversion en moniteur asynchrone
    let mut async_monitor = AsyncMonitorSocket::new(monitor)?;

    println!("🧭 Rustykey en écoute...");

    while let Some(event) = async_monitor.next().await {
        match event {
            Ok(event) => handle_event(event)?,
            Err(e) => eprintln!("Erreur lors de la réception de l'événement: {}", e),
        }
    }

    Ok(())
}

fn handle_event(event: tokio_udev::Event) -> Result<(), Box<dyn std::error::Error>> {

    // On gère les événements d'insertion et de retrait du périphérique
    match event.event_type() {
        tokio_udev::EventType::Add => {
            if let Some(devnode) = event.devnode(){
                let device_path = devnode.display().to_string(); // Ca donne le chemin genre "/dev/sda1"
                // On vérifie ensuite que c'est bien un périphérique USB et une partition pour la monter
                if event.parent_with_subsystem_devtype("usb", "usb_device")?.is_some() {
                    if let Some(devtype) = event.device().devtype() {
                        if devtype == "partition" {
                            println!("🔌 Partition détectée: {}", device_path);
                            if let Err(e) = set_worker(&device_path) {
                                eprintln!("Erreur montage: {}", e);
                            }
                        } else if devtype == "disk" {
                            println!("🔍 Disque détecté: {}", device_path);
                        }
                    }
                }
            }
        },
        tokio_udev::EventType::Remove => {
            if let Some(devnode) = event.devnode() {
                let device_path = devnode.display().to_string();
                if event.parent_with_subsystem_devtype("usb", "usb_device")?.is_some() {
                    if let Some(devtype) = event.device().devtype() {
                        if devtype == "partition" {
                            println!("🔌 Partition retirée: {}", device_path);
                            // if let Err(e) = unmount_partition(&device_path) {
                            //     eprintln!("Erreur démontage: {}", e);
                            // }
                        } else if devtype == "disk" {
                            println!("🔍 Disque retiré: {}", device_path);
                        }
                    }
                }
            }
        },
        _ => {}
    }

    Ok(())
}

fn set_worker(device_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    // On crée un fork pour que l'enfant travaille son device
    // et le parent continue à écouter les événements udev
    match unsafe { fork()? } {
        ForkResult::Parent { child } => {
            println!("🧑‍💻 Worker lancé (pid {}) pour {}", child, device_path);
            Ok(())
        }
        ForkResult::Child => {
            match manage_device(device_path) {
                Ok(_) => std::process::exit(0),
                Err(e) => {
                    eprintln!("❌ Partition worker error: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }
}

fn manage_device(device_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    create_namespace()?;
    let fs_type: String = get_fs_type(device_path)?;
    let device_name = clean_namespace(device_path)?;
    let mount_path = mount_device(&device_name, fs_type)?;
    // use caps::{Capability, CapSet, clear};
    // use libc::{prctl, PR_SET_NO_NEW_PRIVS};
    // for set in [CapSet::Effective, CapSet::Permitted, CapSet::Inheritable] {
    //     if let Err(e) = clear(None, set) {
    //         eprintln!("Erreur clear caps ({:?}): {}", set, e);
    //     }
    // }
    // println!("✅ Capabilities retirées !");
    
    // // 2. Bloquer toute élévation de privilèges future
    // let res = unsafe { prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    // if res != 0 {
    //     eprintln!("Erreur prctl: {}", std::io::Error::last_os_error());
    // } else {
    //     println!("✅ prctl(PR_SET_NO_NEW_PRIVS, 1) appliqué !");
    // }
    send_files(&mount_path, &device_name)?;
    cleanup_mount(&mount_path)?;
    Ok(())
}

fn create_namespace() -> Result<(), Box<dyn std::error::Error>> {
    // On crée un namespace mount pour isoler les montages
    unshare(CloneFlags::CLONE_NEWNS).expect("❌ unshare échoué");

    // On le rend privé (similaire à mount --make-rprivate /) (pas de partage entre namespaces)
    mount(
        Some("none"),
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE, // MS_PRIVATE pour privé / MS_REC pour récursif
        None::<&str>,
    ).expect("❌ mount --make-rprivate échoué");

    Ok(())
}

fn clean_namespace(device_path: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Préparation du pivot_root
    // On monte un tmpfs ou sera notre nouvelle racine
    let new_root = Path::new("/mnt/newroot");
    mount(
        Some("tmpfs"),
        new_root, 
        Some("tmpfs"), 
        MsFlags::empty(),
        None::<&str>
    ).expect("❌ tmpfs mount échoué");

    // On extrait le nom du device
    let device_name = Path::new(device_path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("unk")
        .to_string();

    // On crée le fichier du device dans notre nouvelle racine 
    let bind_target = new_root.join("dev").join(&device_name);
    create_dir_all(bind_target.parent().unwrap())?;
    File::create(&bind_target)?;

    // On bind-monte le device dans la nouvelle racine
    mount(
        Some(device_path),
        &bind_target,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_RDONLY,
        None::<&str>,
    ).expect("❌ bind-mount device échoué");

    // On crée un dossier pour contenir l'ancienne racine pour le pivot_root
    let old_root = new_root.join(".oldroot");
    create_dir_all(&old_root)?;

    // pivot_root : on change la racine et met l'ancienne dans .oldroot
    chdir(new_root)?;
    pivot_root(".", ".oldroot").expect("❌ pivot_root échoué");
    chdir("/")?;

    // On nettoie l'ancienne racine
    umount2("/.oldroot", MntFlags::MNT_DETACH).ok();
    remove_dir_all("/.oldroot").ok();

    Ok(device_name)
}

fn mount_device(device_name: &str, fs_type: String) -> Result<PathBuf, Box<dyn std::error::Error>> {
    // On crée le dossier pour monter le contenu du périphérique USB
    let usb_content_dir = Path::new("/mnt/usb-content");
    create_dir_all(usb_content_dir)?;
    let mount_path = usb_content_dir.join(device_name);
    create_dir_all(&mount_path)?;

    let dev_in_ns = format!("/dev/{}", device_name);

    // On monte le monte à partir du bind-mount
    mount(
        Some(dev_in_ns.as_str()),
        &mount_path,
        Some(fs_type.as_str()),
        MsFlags::MS_RDONLY,
        None::<&str>,
    ).map_err(|e| format!("❌ Erreur montage filesystem : {:?} pour FS {}", e, fs_type))?;

    println!("✅ Partition {} montée sur {:?}", dev_in_ns, mount_path);

    Ok(mount_path)
}

fn cleanup_mount(mount_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    // Démontage + suppression du dossier
    umount2(mount_path, MntFlags::MNT_DETACH).ok();
    fs::remove_dir_all(mount_path).ok();
    println!("📤 Partition démontée et nettoyée : {:?}", mount_path);
    Ok(())
}

fn get_fs_type(device_path: &str) -> Result<String, Box<dyn std::error::Error>> {
    let output = Command::new("lsblk")
        .args(&["-no", "FSTYPE", device_path])
        .output()?;
    if !output.status.success() {
        return Err(format!("lsblk a échoué sur {}", device_path).into());
    }
    let fs_type = String::from_utf8_lossy(&output.stdout).trim().to_string();

    if fs_type.is_empty() {
        Err(format!("Impossible de détecter le type de FS de {}", device_path).into())
    } else {
        Ok(fs_type)
    }
}

// ─── mêmes structures que le backend ─────────────────────────────────
#[derive(Debug, Serialize, Deserialize)]
struct Manifeste {
    device_id: String,
    session_id: String,
    files: Vec<FileEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct FileEntry {
    path: String,
    size: u64,
}

/// Envoie tous les fichiers présents sous `mount_root` au backend.
/// `device_id` → ex. "sda1"
fn send_files(mount_root: &Path, device_id: &str) -> anyhow::Result<()> {
    // 1. Balayage récursif pour constituer le manifeste
    let mut entries = Vec::<FileEntry>::new();

    for entry in WalkDir::new(mount_root).into_iter().filter_map(Result::ok) {
        if entry.file_type().is_file() {
            let rel = entry.path().strip_prefix(mount_root)?;      // chemin relatif
            let size = entry.metadata()?.len();
            entries.push(FileEntry {
                path: rel.to_string_lossy().to_string(),
                size,
            });
        }
    }

    let manifeste = Manifeste {
        device_id: device_id.to_string(),
        session_id: Uuid::new_v4().to_string(),
        files: entries,
    };

    let manifeste_bytes = serde_json::to_vec(&manifeste)?;

    // 2. Connexion TCP au backend
    let mut stream = TcpStream::connect("127.0.0.1:7878")?;

    // 3. Envoyer la taille du manifeste (u32 big-endian) PUIS le manifeste
    let len = (manifeste_bytes.len() as u32).to_be_bytes();
    stream.write_all(&len)?;
    stream.write_all(&manifeste_bytes)?;

    // 4. Envoyer chaque fichier, dans l'ordre du manifeste
    let mut buf = [0u8; 8192];
    for file in &manifeste.files {
        let mut f = std::fs::File::open(mount_root.join(&file.path))?;
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 { break; }
            stream.write_all(&buf[..n])?;
        }
    }

    println!("🚚 Tous les fichiers envoyés pour {}", device_id);
    Ok(())
}

fn handle_existing_partition(dev: &str) -> Result<(), Box<dyn std::error::Error>> {
    match is_mounted(dev) {
        Some(mount_path) => {
            println!("{} est déjà monté sur {:?}, on démonte et remonte proprement", dev, mount_path);
            match umount2(&mount_path, MntFlags::MNT_DETACH){
                Ok(_) => println!("✅ Démontage réussi de {:?}", mount_path),
                Err(e) => eprintln!("❌ Erreur umount2({:?}): {}", mount_path, e),
            }
            match fs::remove_dir_all(&mount_path){
                Ok(_) => println!("✅ Suppresion réussi de {:?}", mount_path),
                Err(e) => eprintln!("❌ Erreur suppression({:?}): {}", mount_path, e),
            }
            if let Err(e) = set_worker(dev) {
                eprintln!("❌ Erreur lors du remontage de {}: {}", dev, e);
            }
        },
        None => {
            if let Err(e) = set_worker(dev) {
                eprintln!("❌ Erreur lors du lancement du worker pour {}: {}", dev, e);
            }
        }
    }
    Ok(())
}

fn is_mounted(device: &str) -> Option<PathBuf> {
    let file = File::open("/proc/mounts").ok()?;
    for line in BufReader::new(file).lines() {
        if let Ok(l) = line {
            // Format: <device> <mount_point> ...
            let mut fields = l.split_whitespace();
            if let (Some(dev), Some(mount_point)) = (fields.next(), fields.next()) {
                if dev == device {
                    return Some(PathBuf::from(mount_point));
                }
            }
        }
    }
    None
}