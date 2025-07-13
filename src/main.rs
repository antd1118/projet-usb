use std::process::Command;
use std::time::Duration;
use tokio::time::sleep;
use std::collections::HashSet;

#[tokio::main]
async fn main() {
    println!("=== Detecton USB ===");
    
    let mut last_devices = get_usb_devices();
    println!("Nombre de périphériques USB connectés au démarrage: {}", last_devices.len());
    
    for device in &last_devices {
        println!("📱 {}", device);
    }
    
    println!("\n🔍 Surveillance en cours... Branchez/débranchez un périphérique USB");
    
    loop {
        sleep(Duration::from_secs(1)).await;
        
        let current_devices = get_usb_devices();
        
        // Détecter les nouveaux périphériques
        for device in &current_devices {
            if !last_devices.contains(device) {
                println!("🔌 CONNECTÉ: {}", device);
            }
        }
        
        // Détecter les périphériques déconnectés
        for device in &last_devices {
            if !current_devices.contains(device) {
                println!("🔓 DÉCONNECTÉ: {}", device);
            }
        }
        
        last_devices = current_devices;
    }
}

fn get_usb_devices() -> HashSet<String> {
    let mut devices = HashSet::new();
    
    match Command::new("lsusb").arg("-t").output() {
        Ok(output) => {
            let output_str = String::from_utf8_lossy(&output.stdout);
            
            for line in output_str.lines() {
                if line.contains("Class=Mass Storage") {
                    devices.insert(line.to_string());
                }
            }
        }
        Err(e) => {
            eprintln!("Erreur lsusb -t: {}", e);
        }
    }
    
    devices
}