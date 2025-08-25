use tokio_udev::{AsyncMonitorSocket, MonitorBuilder, Enumerator, EventType};
use tokio_stream::StreamExt;
use tokio::sync::mpsc;
use std::ffi::OsStr;
use std::path::PathBuf;
use anyhow::Result;

use crate::device_manager::UsbDevice;
use shared::AgentNotification;

/// Fonction pour écouter les événements USB
pub async fn monitor_usb_devices(
    device_tx: mpsc::UnboundedSender<UsbDevice>,
    notification_tx: mpsc::UnboundedSender<AgentNotification>,
) -> Result<()> {
    println!("🔌 Démarrage du monitoring USB...");

    // Gerons le cas ou il y a déjà un périphérique branché et monté au démarrage de l'agent
    let mut enumerator = Enumerator::new()?;
    enumerator.match_subsystem("block")?;
    
    for device in enumerator.scan_devices()? {
        let is_usb = device.property_value("ID_USB_DRIVER").is_some()
            || device.property_value("ID_BUS").map_or(false, |v| v == "usb");
        let is_partition = device.property_value("DEVTYPE").map_or(false, |v| v == "partition");
        
        if is_usb && is_partition {
            if let Some(devnode) = device.devnode() {
                let device_path = devnode.display().to_string();
                println!("🔌 Périphérique USB déjà présent : {}", device_path);
                //Je voulais le démonter du FS principal mais pas possible car le service account n'a pas les droits (dossier /media/user propriétaire), il faudrait une cap en plus mais ca diminuerait la sécurité
                println!("⚠️  Veuillez le débrancher et le rebrancher");
            }
        }
    }

    // On crée le moniteur asynchrone pour les nouveaux events
    let monitor = MonitorBuilder::new()?
        .match_subsystem("block")?
        .listen()?;

    let mut async_monitor = AsyncMonitorSocket::new(monitor)?;
    println!("👂 Rustykey en écoute...");

    while let Some(event) = async_monitor.next().await {
        match event {
            Ok(event) => {
                if let Err(e) = handle_event(event, &device_tx, &notification_tx).await {
                    eprintln!("❌ Erreur handling event: {}", e);
                }
            }
            Err(e) => eprintln!("❌ Erreur réception event: {}", e),
        }
    }

    Ok(())
}

// Fonction pour gérer les événements usb (ajout et retrait)
async fn handle_event(
    event: tokio_udev::Event,
    device_tx: &mpsc::UnboundedSender<UsbDevice>,
    notification_tx: &mpsc::UnboundedSender<AgentNotification>,
) -> Result<()> {
    match event.event_type() {
        EventType::Add => {
            let is_usb = event.parent_with_subsystem_devtype("usb", "usb_device")?.is_some();
            let is_partition = event.device().devtype()
                .as_deref()
                .map_or(false, |t| t == OsStr::new("partition"));

            if is_usb && is_partition {
                if let Some(devnode) = event.devnode() {
                    let device_path = devnode.display().to_string();
                    let device_id = event
                        .device()
                        .property_value("ID_SERIAL_SHORT")
                        .map(|s| s.to_string_lossy().to_ascii_lowercase())
                        .unwrap_or_else(|| "inconnu".into());

                    println!("🔌 Périphérique inséré: {}. Numéro de série: {}", device_path, device_id);

                    // On récupère les infos du device
                    let usb_device = UsbDevice::new(
                        device_id.clone(), 
                        PathBuf::from(device_path)
                    );

                    // On l'envoie au cannal pour montage
                    if let Err(e) = device_tx.send(usb_device) {
                        eprintln!("❌ Erreur envoi device: {}", e);
                        return Err(anyhow::anyhow!("❌ Erreur envoi device"));
                    }
                }
            }
        }
        EventType::Remove => {
            let is_usb = event.parent_with_subsystem_devtype("usb", "usb_device")?.is_some();
            let is_partition = event.device().devtype()
                .as_deref()
                .map_or(false, |t| t == OsStr::new("partition"));

            if is_usb && is_partition {
                if let Some(devnode) = event.devnode() {
                    let device_path = devnode.display().to_string();
                    println!("🔌 Périphérique retiré: {}", device_path);
                    
                    let device_id = event
                        .device()
                        .property_value("ID_SERIAL_SHORT")
                        .map(|s| s.to_string_lossy().to_ascii_lowercase())
                        .unwrap_or_else(|| {
                            // Essaye depuis device_path sinon
                            device_path.split('/').last().unwrap_or("unknown").to_string()
                        });
                    
                    println!("🗑️ Nettoyage device_id: {}", device_id);
            
                    // todo démontage
                    if let Err(e) = notification_tx.send(AgentNotification::DeviceDisconnected { device_id }) {
                        eprintln!("❌ Erreur envoi notification déconnexion: {}", e);
                        return Err(anyhow::anyhow!("Erreur envoi notification déconnexion"));
                    }
                }
            }
        }
        _ => {}
    }

    Ok(())
}