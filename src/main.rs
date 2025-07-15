use tokio_udev::{AsyncMonitorSocket, MonitorBuilder};
use tokio_stream::StreamExt;
use std::process::Command;
use std::fs;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    ensure_service_account_exists()?;
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
                    
                    // Vérifier que c'est bien une partition (devtype == "partition")
                    if let Some(devtype) = event.device().devtype() {
                        if devtype == "partition" {
                            println!("🔌 Partition détectée: {}", path);
                            if let Err(e) = mount_partition(&path) {
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

fn ensure_service_account_exists() -> Result<(), Box<dyn std::error::Error>> {
    let status = Command::new("id").arg("usb-agent").status()?;
    if !status.success() {
        println!("👤 Création de l'utilisateur usb-agent...");
        let create = Command::new("useradd")
            .args(&["-r", "-M", "-s", "/usr/sbin/nologin", "usb-agent"]) //-r: compte système, -M: pas de répertoire personnel, -s: pas d'acces shell
            .status()?;
        if !create.success() {
            return Err("Échec de création de l'utilisateur usb-agent".into());
        }
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
    let full_path = format!("/mnt/usb-agent/{}", device_name);
    fs::create_dir_all(&full_path)?;

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
        mount_cmd.args(&["-o", &options, path, &full_path]);
    } else {
        // Ext, XFS, Btrfs → montage standard
        mount_cmd.args(&[path, &full_path]);
    }

    let status = mount_cmd.status()?;
    if !status.success() {
        return Err(format!("Échec du montage de {}", path).into());
    }

    // Post-montage : chmod/chown pour systèmes de fichiers POSIX
    if !["vfat", "exfat", "ntfs"].contains(&fs_type.as_str()) {
        let chown = Command::new("chown")
            .args(&["usb-agent:usb-agent", &full_path])
            .status()?;
        if !chown.success() {
            return Err(format!("Échec du chown sur {}", full_path).into());
        }

        let chmod = Command::new("chmod")
            .args(&["700", &full_path])
            .status()?;
        if !chmod.success() {
            return Err(format!("Échec du chmod sur {}", full_path).into());
        }
    }

    println!("✅ Partition {} montée sur {}", path, full_path);
    Ok(())
}

fn unmount_partition(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let device_name = path.split('/').last().unwrap_or("unk");
    let full_path = format!("/mnt/usb-agent/{}", device_name);

    // Vérifie si le point est monté
    let status = Command::new("mountpoint")
        .arg("-q")
        .arg(&full_path)
        .status()?;

    if !status.success() {
        println!("⚠️ {} n'est pas un point de montage actif. Ignoré.", full_path);
        return Ok(());
    }

    // Démontage
    let umount_status = Command::new("umount")
        .arg(&full_path)
        .status()?;

    if !umount_status.success() {
        return Err(format!("❌ Échec du démontage de {}", full_path).into());
    }

    // Supprime le dossier s'il existe
    if let Err(e) = fs::remove_dir_all(&full_path) {
        eprintln!("⚠️ Dossier non supprimé ({}): {}", full_path, e);
    }

    println!("📤 Démontage réussi de {}", full_path);
    Ok(())
}
