use tokio_udev::{AsyncMonitorSocket, MonitorBuilder};
use tokio_stream::StreamExt;
use std::process::Command;
use std::fs;
use std::path::Path;

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
            let devnode = event.devnode().map(|d| d.display().to_string());
            if let Some(node) = devnode {
                // Vérifier que c'est bien un périphérique USB
                if let Ok(Some(parent)) = event.parent_with_subsystem_devtype("usb", "usb_device") {
                    let product = parent.attribute_value("product")
                        .map(|v| v.to_str().unwrap_or("Inconnu"))
                        .unwrap_or("Inconnu");

                    if node.chars().last().map_or(false, |c| c.is_numeric()) {
                        println!("🔌 Partition détectée: {} ({})", node, product);
                        mount_partition_for_usb_agent(&node)?;
                    } else {
                    println!("🔍 Disque détecté (non monté): {}", node);
                    }
                }
            }
        },
        tokio_udev::EventType::Remove => println!("Périphérique retiré"),
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


fn get_fs_type(devnode: &str) -> Result<String, Box<dyn std::error::Error>> {
    let output = Command::new("blkid")
        .arg(devnode)
        .output()?;

    if !output.status.success() {
        return Err(format!("Erreur blkid sur {}", devnode).into());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    for part in stdout.split_whitespace() {
        if part.starts_with("TYPE=") {
            return Ok(part.trim_start_matches("TYPE=").trim_matches('"').to_string());
        }
    }

    Err("Impossible de déterminer le type de système de fichiers".into())
}



fn mount_partition_for_usb_agent(devnode: &str) -> Result<(), Box<dyn std::error::Error>> {
    let device_name = devnode.split('/').last().unwrap_or("unk");
    let mount_point = format!("/mnt/usb-agent/{}", device_name);
    fs::create_dir_all(&mount_point)?;

    let fs_type = get_fs_type(devnode)?;
    println!("📦 Système de fichiers détecté pour {}: {}", devnode, fs_type);

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
        mount_cmd.args(&["-o", &options, devnode, &mount_point]);
    } else {
        // Ext, XFS, Btrfs → montage standard
        mount_cmd.args(&[devnode, &mount_point]);
    }

    let status = mount_cmd.status()?;
    if !status.success() {
        return Err(format!("Échec du montage de {}", devnode).into());
    }

    // Post-montage : chmod/chown pour systèmes de fichiers POSIX
    if !["vfat", "exfat", "ntfs"].contains(&fs_type.as_str()) {
        let chown = Command::new("chown")
            .args(&["usb-agent:usb-agent", &mount_point])
            .status()?;
        if !chown.success() {
            return Err(format!("Échec du chown sur {}", mount_point).into());
        }

        let chmod = Command::new("chmod")
            .args(&["700", &mount_point])
            .status()?;
        if !chmod.success() {
            return Err(format!("Échec du chmod sur {}", mount_point).into());
        }
    }

    println!("✅ Partition {} montée sur {}", devnode, mount_point);
    Ok(())
}

