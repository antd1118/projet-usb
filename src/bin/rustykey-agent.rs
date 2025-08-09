use tokio_udev::{AsyncMonitorSocket, MonitorBuilder, Enumerator};
use tokio_stream::StreamExt;
use tokio::process::Command;
use std::path::PathBuf;
use nix::mount::{umount2, MntFlags};
use std::fs::{self, File};
use std::io::{BufReader, BufRead};
use std::process::Stdio;
use std::ffi::OsStr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    // Gerons le cas ou il y a déjà un périphérique branché et monté au démarrage de l'agent

    let mut enumerator = Enumerator::new()?;

    enumerator.match_subsystem("block")?;
    for device in enumerator.scan_devices()? {
        // On vérifie que c'est une partition USB
        let is_usb = device.property_value("ID_USB_DRIVER").is_some()
            || device.property_value("ID_BUS").map_or(false, |v| v == "usb");
        let is_partition = device.property_value("DEVTYPE").map_or(false, |v| v == "partition");
        if is_usb && is_partition {
            if let Some(devnode) = device.devnode() {
                let device_path = devnode.display().to_string();
                println!("Périphérique USB déjà présent : {}", device_path);
                //handle_existing_partition(&device_path)?; Je voulais le démonter du FS principal mais pas possible car le service account n'a pas les droits (dossier /media/user propriétaire), il faudrait une cap en plus mais ca diminuerait la sécurité
                println!("Veuillez le débrancher et le rebrancher");
            } else {
                println!("Périphérique USB détecté mais sans partition");
            }
        }
    }

    // Création du moniteur synchrone
    let monitor = MonitorBuilder::new()?
        .match_subsystem("block")?
        .listen()?;

    // Conversion en moniteur asynchrone
    let mut async_monitor = AsyncMonitorSocket::new(monitor)?;

    println!("Rustykey en écoute...");

    while let Some(event) = async_monitor.next().await {
        match event {
            Ok(event) => handle_event(event)?,
            Err(e) => eprintln!("Erreur lors de la réception de l'événement: {}", e),
        }
    }

    Ok(())
}

fn handle_event(event: tokio_udev::Event) -> anyhow::Result<()> {

    // On gère les événements d'insertion et de retrait du périphérique
    match event.event_type() {
        tokio_udev::EventType::Add => {
            // On vérifie que c'est bien un périphérique USB avec partition
            let is_usb = event.parent_with_subsystem_devtype("usb", "usb_device")?.is_some();
            let is_partition = event.device().devtype()
                .as_deref()
                .map_or(false, |t| t == OsStr::new("partition"));
                if is_usb && is_partition {

                    if let Some(devnode) = event.devnode() {
                        // On récupère le chemin du périphérique (/dev/sda1 par exemple)
                        let device_path = devnode.display().to_string();
                        // On récupère le numéro de série du périphérique
                        let device_id = event
                            .device()
                            .property_value("ID_SERIAL_SHORT")
                            .map(|s| s.to_string_lossy().to_ascii_lowercase())
                            .unwrap_or_else(|| "inconnu".into());

                        println!("Périphérique inséré: {}. Numéro de série: {}", device_path, device_id);

                        // On lance le worker en lui passant le chemin device à monter et le numéro de série
                        tokio::spawn(async move {
                            let status = Command::new("/usr/local/bin/rustykey-worker")
                                .arg(&device_path)
                                .arg(&device_id)
                                .stdout(Stdio::inherit())
                                .stderr(Stdio::inherit())
                                .status()
                                .await;
                            match status {
                                Ok(status) => println!("Traitement du périphérique (worker) terminé !"),
                                Err(e) => eprintln!("Erreur au lancement du worker: {e}"),
                            }
                        });
                    }
                }
            }
        tokio_udev::EventType::Remove => {
            let is_usb = event.parent_with_subsystem_devtype("usb", "usb_device")?.is_some();
            let is_partition = event.device().devtype()
                .as_deref()
                .map_or(false, |t| t == OsStr::new("partition"));
            if is_usb && is_partition {
                if let Some(devnode) = event.devnode() {
                    let device_path = devnode.display().to_string();
                    println!("Périphérique retirée: {}", device_path);
                    // if let Err(e) = unmount_partition(&device_path) {
                    //     eprintln!("Erreur démontage: {}", e);
                    // }
                }
            }
        }
        _ => {}
    }

    Ok(())
}

fn handle_existing_partition(dev: &str) -> Result<(), Box<dyn std::error::Error>> {
    let dev_owned = dev.to_owned();
    if let Some(mount_path) = is_mounted(dev) {
        println!("{} est déjà monté sur {:?}, on démonte et remonte proprement", dev, &mount_path);

        if let Err(e) = umount2(&mount_path, MntFlags::MNT_DETACH) {
            eprintln!("Erreur umount2({:?}): {}", &mount_path, e);
        } else {
            println!("Démontage réussi de {:?}", &mount_path);
        }

        if let Err(e) = fs::remove_dir_all(&mount_path) {
            eprintln!("Erreur suppression({:?}): {}", &mount_path, e);
        } else {
            println!("Suppression réussie de {:?}", &mount_path);
        }
    }

    tokio::spawn(async move {
        match Command::new("/usr/local/bin/rustykey-worker")
            .arg(&dev_owned)
            .status()
            .await
        {
            Ok(status) => {
                if !status.success() {
                    eprintln!("rustykey-worker a échoué avec le code {:?}", status.code());
                }
            }
            Err(e) => {
                eprintln!("Erreur lors de l'exécution du worker : {}", e);
            }
        }
    });

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