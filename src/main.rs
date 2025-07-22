use tokio_udev::{AsyncMonitorSocket, MonitorBuilder};
use tokio_stream::StreamExt;
use std::process::{Command, exit};
use std::path::Path;
use std::collections::HashSet;
use nix::sched::{unshare, CloneFlags};
use nix::mount::{mount, umount2, MsFlags, MntFlags};
use nix::unistd::{fork, ForkResult, pivot_root, chdir};
use std::fs::{self, create_dir_all, remove_dir_all, write};
use std::os::unix::prelude::PermissionsExt;
use std::thread;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    // 🔎 Gérer les périphériques déjà présents
    let existing = get_existing_usb_partitions();

    for dev in existing {
        if is_mounted(&dev) {
            println!("⚠️ Déjà monté automatiquement : {} → on démonte et remonte proprement", dev);
            unmount_partition(&dev)?;
            if let Err(e) = mount_partition(&dev) {
                eprintln!("❌ Erreur lors du remontage de {}: {}", dev, e);
            }
        }
    }

    // Création du moniteur synchrone
    let monitor = MonitorBuilder::new()?
        .match_subsystem("block")?
        .listen()?;

    // Conversion en moniteur asynchrone
    let mut async_monitor = AsyncMonitorSocket::new(monitor)?;

    println!("🧭 Agent USB (async) en écoute...");
    // Boucle asynchrone sur les événements
    while let Some(event) = async_monitor.next().await {
        match event {
            Ok(event) => handle_event(event)?,
            Err(e) => eprintln!("Erreur lors de la réception de l'événement: {}", e),
        }
    }

    Ok(())
}

fn handle_event(event: tokio_udev::Event) -> Result<(), Box<dyn std::error::Error>> {

    // Traitement spécifique selon le type d'événement
    match event.event_type() {
        tokio_udev::EventType::Add => {
            if let Some(devnode) = event.devnode(){
                let path = devnode.display().to_string();
                // Vérifier que c'est bien un périphérique USB
                if event.parent_with_subsystem_devtype("usb", "usb_device")?.is_some() {
                    
                    // Vérifier que c'est bien une partition
                    if let Some(devtype) = event.device().devtype() {
                        if devtype == "partition" {
                            println!("🔌 Partition détectée: {}", path);
                            if let Err(e) = spawn_worker_for_partition(&path) {
                                eprintln!("Erreur montage: {}", e);
                            }
                        } else if devtype == "disk" {
                            println!("🔍 Disque détecté: {}", path);
                        }
                    }
                }
            }
        },
        tokio_udev::EventType::Remove => {
            if let Some(devnode) = event.devnode() {
                let path = devnode.display().to_string();
                // Vérifier que c'est bien un périphérique USB
                if event.parent_with_subsystem_devtype("usb", "usb_device")?.is_some() {
                    // Vérifier que c'est bien une partition (devtype == "partition")
                    if let Some(devtype) = event.device().devtype() {
                        if devtype == "partition" {
                            println!("🔌 Partition retirée: {}", path);
                            if let Err(e) = unmount_partition(&path) {
                                eprintln!("Erreur démontage: {}", e);
                            }
                        } else if devtype == "disk" {
                            println!("🔍 Disque retiré: {}", path);
                        }
                    }
                }
            }
        },
        _ => {}
    }

    Ok(())
}

fn get_fs_type(path: &str) -> Result<String, Box<dyn std::error::Error>> {
    let output = Command::new("blkid")
        .arg(path)
        .output()?;

    if !output.status.success() {
        return Err(format!("Erreur blkid sur {}", path).into());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    for part in stdout.split_whitespace() {
        if part.starts_with("TYPE=") {
            return Ok(part.trim_start_matches("TYPE=").trim_matches('"').to_string());
        }
    }

    Err("Impossible de déterminer le type de système de fichiers".into())
}



fn mount_partition(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let device_name = path.split('/').last().unwrap_or("unk");
    let mount_path = format!("/mnt/usb-agent/{}", device_name);

    fs::create_dir_all(&mount_path)?;
    let chown = Command::new("chown")
        .args(&["usb-agent:usb-agent", "/mnt/usb-agent"])
        .status()?;
    if !chown.success() {
        return Err(format!("Échec du chown sur {}", mount_path).into());
    }

    let chmod = Command::new("chmod")
        .args(&["700", "/mnt/usb-agent"])
        .status()?;
    if !chmod.success() {
        return Err(format!("Échec du chmod sur {}", mount_path).into());
    }  

    let fs_type = get_fs_type(path)?;
    println!("📦 Système de fichiers détecté pour {}: {}", path, fs_type);

    // Type de montage
    let mut mount_cmd = Command::new("mount");

    if ["vfat", "exfat", "ntfs"].contains(&fs_type.as_str()) {
        // Récupérer l'uid/gid de usb-agent
        let uid = users::get_user_by_name("usb-agent")
            .ok_or("Utilisateur usb-agent introuvable")?
            .uid()
            .to_string();
        let gid = users::get_group_by_name("usb-agent")
            .ok_or("Groupe usb-agent introuvable")?
            .gid()
            .to_string();

        let options = format!("uid={},gid={},umask=077", uid, gid);
        mount_cmd.args(&["-o", &options, path, &mount_path]);
    } else {
        // Ext, XFS, Btrfs → montage standard
        mount_cmd.args(&[path, &mount_path]);
    }

    let status = mount_cmd.status()?;
    if !status.success() {
        return Err(format!("Échec du montage de {}", path).into());
    }

    // Post-montage : chmod/chown pour systèmes de fichiers POSIX
    if !["vfat", "exfat", "ntfs"].contains(&fs_type.as_str()) {
        let chown = Command::new("chown")
            .args(&["usb-agent:usb-agent", &mount_path])
            .status()?;
        if !chown.success() {
            return Err(format!("Échec du chown sur {}", mount_path).into());
        }

        let chmod = Command::new("chmod")
            .args(&["700", &mount_path])
            .status()?;
        if !chmod.success() {
            return Err(format!("Échec du chmod sur {}", mount_path).into());
        }
    }

    println!("✅ Partition {} montée sur {}", path, mount_path);
    Ok(())
}

fn unmount_partition(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let device_name = path.split('/').last().unwrap_or("unk");
    let mount_path = format!("/mnt/usb-agent/{}", device_name);

    // Vérifie si le point est monté
    let status = Command::new("mountpoint")
        .arg("-q")
        .arg(&mount_path)
        .status()?;

    if !status.success() {
        println!("⚠️ {} n'est pas un point de montage actif. Ignoré.", mount_path);
        return Ok(());
    }

    // Démontage
    let umount_status = Command::new("umount")
        .arg(&mount_path)
        .status()?;

    if !umount_status.success() {
        return Err(format!("❌ Échec du démontage de {}", mount_path).into());
    }

    // Supprime le dossier s'il existe
    if let Err(e) = fs::remove_dir_all(&mount_path) {
        eprintln!("⚠️ Dossier non supprimé ({}): {}", mount_path, e);
    }

    println!("📤 Démontage réussi de {}", mount_path);
    Ok(())
}

fn get_existing_usb_partitions() -> HashSet<String> {
    let mut partitions = HashSet::new();

    let output = Command::new("lsblk")
        .args(["-o", "NAME,TRAN", "-nr"])
        .output()
        .expect("échec de lsblk");

    let output_str = String::from_utf8_lossy(&output.stdout);

    for line in output_str.lines() {
        let parts: Vec<&str> = line.trim().split_whitespace().collect();
        if parts.len() == 2 && parts[1] == "usb" {
            // ex: sdb1 => /dev/sdb1
            partitions.insert(format!("/dev/{}", parts[0]));
        }
    }

    partitions
}

fn is_mounted(device: &str) -> bool {
    let output = Command::new("findmnt")
        .args(["-n", "-o", "TARGET", device])
        .output()
        .ok()
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false);

    output
}



/// Configure les maps UID/GID après un unshare(CLONE_NEWUSER)
fn setup_uid_gid_maps() -> std::io::Result<()> {
    // Nécessaire pour autoriser l'écriture dans gid_map
    write("/proc/self/setgroups", b"deny")?;

    // uid_map : mappe uid 0 dans le namespace vers uid réel
    let uid_map = format!("0 {} 1\n", nix::unistd::getuid().as_raw());
    write("/proc/self/uid_map", uid_map)?;

    // gid_map : pareil pour gid
    let gid_map = format!("0 {} 1\n", nix::unistd::getgid().as_raw());
    write("/proc/self/gid_map", gid_map)?;

    Ok(())
}

fn spawn_worker_for_partition(partition: &str) -> Result<(), Box<dyn std::error::Error>> {
    match unsafe { fork()? } {
        ForkResult::Parent { child } => {
            println!("🧑‍💻 Worker lancé (pid {}) pour {}", child, partition);
            Ok(())
        }
        ForkResult::Child => {
            // --- Enfant : début isolement avec user+mount namespace ---
            nix::sched::unshare(CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNS)
                .expect("unshare échoué");

            // Obligatoire : configurer les mappings UID/GID pour avoir CAP_SYS_ADMIN localement
            setup_uid_gid_maps().expect("uid/gid map échouée");

            // Isolation mount : rendre les montages privés
            mount(
                Some("none"),
                "/",
                None::<&str>,
                MsFlags::MS_REC | MsFlags::MS_PRIVATE,
                None::<&str>,
            ).expect("mount --make-rprivate échoué");

            // Préparer racine temporaire
            let new_root = Path::new("/mnt/newroot");
            let old_root = new_root.join(".oldroot");

            create_dir_all(&old_root)?;

            mount(Some("tmpfs"), new_root, Some("tmpfs"), MsFlags::empty(), None::<&str>)
                .expect("tmpfs mount échoué");

            pivot_root(new_root, &old_root).expect("pivot_root échoué");

            chdir("/")?;

            umount2("/.oldroot", MntFlags::MNT_DETACH).ok();
            remove_dir_all("/.oldroot").ok();

            // Préparer point de montage
            let device_name = Path::new(partition)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("unk");
            let mount_path = format!("/mnt/{}", device_name);
            create_dir_all(&mount_path)?;

            // Monter la partition réelle (dans l’environnement isolé !)
            mount(
                Some(partition),
                mount_path.as_str(),
                None::<&str>,
                MsFlags::MS_RDONLY,
                None::<&str>,
            ).map_err(|e| format!("Erreur montage : {:?}", e))?;

            println!("✅ [Worker] Partition {} montée dans un mount namespace isolé !", partition);

            // -- Simulation traitement --
            thread::sleep(Duration::from_secs(30));

            // Nettoyage
            umount2(mount_path.as_str(), MntFlags::MNT_DETACH).ok();
            fs::remove_dir_all(&mount_path).ok();

            println!("📤 [Worker] Partition {} démontée, worker terminé.", partition);

            std::process::exit(0);
        }
    }
}
