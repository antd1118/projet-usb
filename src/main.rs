use tokio_udev::{AsyncMonitorSocket, MonitorBuilder};
use tokio_stream::StreamExt;
use std::process::{Command, exit};
use std::path::{Path, PathBuf};
use std::collections::HashSet;
use nix::sched::{unshare, CloneFlags};
use nix::mount::{mount, umount2, MsFlags, MntFlags};
use nix::unistd::{fork, ForkResult, pivot_root, chdir};
use std::fs::{self, create_dir_all, remove_dir_all, write, File};
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
                let device_path = devnode.display().to_string();
                // Vérifier que c'est bien un périphérique USB
                if event.parent_with_subsystem_devtype("usb", "usb_device")?.is_some() {
                    
                    // Vérifier que c'est bien une partition
                    if let Some(devtype) = event.device().devtype() {
                        if devtype == "partition" {
                            println!("🔌 Partition détectée: {}", device_path);
                            if let Err(e) = spawn_worker_for_partition(&device_path) {
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
                // Vérifier que c'est bien un périphérique USB
                if event.parent_with_subsystem_devtype("usb", "usb_device")?.is_some() {
                    // Vérifier que c'est bien une partition (devtype == "partition")
                    if let Some(devtype) = event.device().devtype() {
                        if devtype == "partition" {
                            println!("🔌 Partition retirée: {}", device_path);
                            if let Err(e) = unmount_partition(&device_path) {
                                eprintln!("Erreur démontage: {}", e);
                            }
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

fn get_fs_type(device_path: &str) -> Result<String, Box<dyn std::error::Error>> {
    let output = Command::new("blkid")
        .arg(device_path)
        .output()?;

    if !output.status.success() {
        return Err(format!("Erreur blkid sur {}", device_path).into());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    for part in stdout.split_whitespace() {
        if part.starts_with("TYPE=") {
            return Ok(part.trim_start_matches("TYPE=").trim_matches('"').to_string());
        }
    }

    Err("Impossible de déterminer le type de système de fichiers".into())
}



fn mount_partition(device_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let device_name = device_path.split('/').last().unwrap_or("unk");
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

    let fs_type = get_fs_type(device_path)?;
    println!("📦 Système de fichiers détecté pour {}: {}", device_path, fs_type);

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
        mount_cmd.args(&["-o", &options, device_path, &mount_path]);
    } else {
        // Ext, XFS, Btrfs → montage standard
        mount_cmd.args(&[device_path, &mount_path]);
    }

    let status = mount_cmd.status()?;
    if !status.success() {
        return Err(format!("Échec du montage de {}", device_path).into());
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

    println!("✅ Partition {} montée sur {}", device_path, mount_path);
    Ok(())
}

fn unmount_partition(device_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let device_name = device_path.split('/').last().unwrap_or("unk");
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

fn spawn_worker_for_partition(device_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    match unsafe { fork()? } {
        ForkResult::Parent { child } => {
            println!("🧑‍💻 Worker lancé (pid {}) pour {}", child, device_path);
            Ok(())
        }
        ForkResult::Child => {
            // 1. Isoler le namespace mount
            unshare(CloneFlags::CLONE_NEWNS).expect("❌ unshare échoué");

            // 2. Isolation mount propagation
            mount(
                Some("none"),
                "/",
                None::<&str>,
                MsFlags::MS_REC | MsFlags::MS_PRIVATE,
                None::<&str>,
            ).expect("❌ mount --make-rprivate échoué");

            // 3. Préparer racine temporaire
            let new_root = Path::new("/mnt/newroot");
            mount(Some("tmpfs"), new_root, Some("tmpfs"), MsFlags::empty(), None::<&str>)
                .expect("❌ tmpfs mount échoué");

            // 4. Créer dev/ dans tmpfs
            let dev_dir = new_root.join("dev");
            create_dir_all(&dev_dir)?;

            let device_name = Path::new(device_path)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("unk");

            // 5. Créer fichier cible dans /mnt/newroot/dev/<sdX1>
            let bind_target = dev_dir.join(device_name);
            File::create(&bind_target)?;

            // 6. Bind-mount réel device → dans le futur namespace
            mount(
                Some(device_path),
                &bind_target,
                None::<&str>,
                MsFlags::MS_BIND | MsFlags::MS_RDONLY,
                None::<&str>,
            ).expect("❌ bind-mount device échoué");

            // 7. Créer /.oldroot
            let old_root = new_root.join(".oldroot");
            create_dir_all(&old_root)?;

            // 8. Chdir vers new_root, sinon pivot_root échoue
            chdir(new_root)?;
            pivot_root(".", ".oldroot").expect("❌ pivot_root échoué");
            chdir("/")?;

            // 9. Nettoyage oldroot
            umount2("/.oldroot", MntFlags::MNT_DETACH).ok();
            remove_dir_all("/.oldroot").ok();

            // 10. Créer /mnt/usb-content/<device>
            create_dir_all("/mnt/usb-content")?;
            let mount_path = Path::new("/mnt/usb-content").join(device_name);
            create_dir_all(&mount_path)?;

            // 11. Faire mount interne dans le namespace (pour lecture)
            let dev_in_ns = format!("/dev/{}", device_name);
            mount(
                Some(dev_in_ns.as_str()),
                &mount_path,
                Some("vfat"),
                 MsFlags::MS_RDONLY,
                None::<&str>,
            ).map_err(|e| format!("❌ Erreur montage filesystem : {:?}", e))?;

            println!("✅ [Worker] Partition {} bind-mountée dans namespace isolé !", device_path);

            // 12. Simulation
            thread::sleep(Duration::from_secs(30));

            umount2(&mount_path, MntFlags::MNT_DETACH).ok();
            fs::remove_dir_all(&mount_path).ok();

            println!("📤 [Worker] Partition {} démontée, worker terminé.", device_path);
            std::process::exit(0);
        }
    }
}
