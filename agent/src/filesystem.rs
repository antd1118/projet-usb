use std::path::PathBuf;
use std::collections::HashMap;

use shared::{FileEntry, AgentResponse};
use crate::mount::UsbDevice;

// Contient tous les périphériques
pub struct FileSystemHandler {
    devices: HashMap<String, UsbDevice>,
}

// Pour faire les opérations dans le mount_path des périphériques
impl FileSystemHandler {
    pub fn new() -> Self {
        Self {
            devices: HashMap::new(),
        }
    }

    pub fn add_device(&mut self, device: UsbDevice) {
        println!("📁 Ajout du device {} au gestionnaire de fichiers", device.device_id);
        self.devices.insert(device.device_id.clone(), device);
    }

    pub async fn remove_device(&mut self, device_id: &str) {
        if let Some(mut device) = self.devices.remove(device_id) {
            println!("🧹 Nettoyage device: {}", device_id);
            
            // Fermer proprement les connexions
            let _ = device.unmount_device().await;
        } else {
            println!("⚠️ Device {} déjà nettoyé ou inexistant", device_id);
        }
    }

    pub async fn list_files(&mut self, path: &str) -> AgentResponse {
        // Prendre le premier device connecté
        if let Some(device) = self.devices.values_mut().next() {
            match device.list_files_ipc(path).await {
                Ok(files) => AgentResponse::FileList { files },
                Err(e) => AgentResponse::Error { 
                    message: format!("Failed to list files: {}", e) 
                },
            }
        } else {
            AgentResponse::Error { 
                message: "No device connected".to_string() 
            }
        }
    }

    pub async fn read_file(&mut self, path: &str) -> AgentResponse {
        if let Some(device) = self.devices.values_mut().next() {
            match device.read_file_ipc(path).await {
                Ok(data) => AgentResponse::FileData { data },
                Err(e) => AgentResponse::Error { 
                    message: format!("Failed to read file: {}", e) 
                },
            }
        } else {
            AgentResponse::Error { 
                message: "No device connected".to_string() 
            }
        }
    }

    pub async fn write_file(&mut self, path: &str, data: Vec<u8>) -> AgentResponse {
        if path.is_empty() {
            return AgentResponse::Error { 
                message: "Cannot write to root".to_string() 
            };
        }

        if let Some(device) = self.devices.values_mut().next() {
            match device.write_file_ipc(path, data).await {
                Ok(_) => AgentResponse::Success,
                Err(e) => AgentResponse::Error { 
                    message: format!("Failed to write file: {}", e) 
                },
            }
        } else {
            AgentResponse::Error { 
                message: "No device connected".to_string() 
            }
        }
    }

    pub async fn delete_file(&mut self, path: &str) -> AgentResponse {
        if path.is_empty() {
            return AgentResponse::Error { 
                message: "Cannot delete root".to_string() 
            };
        }

        if let Some(device) = self.devices.values_mut().next() {
            match device.delete_file_ipc(path).await {
                Ok(_) => AgentResponse::Success,
                Err(e) => AgentResponse::Error { 
                    message: format!("Failed to delete: {}", e) 
                },
            }
        } else {
            AgentResponse::Error { 
                message: "No device connected".to_string() 
            }
        }
    }

    pub async fn create_directory(&mut self, path: &str) -> AgentResponse {
        if path.is_empty() {
            return AgentResponse::Error { 
                message: "Cannot create directory at root".to_string() 
            };
        }

        if let Some(device) = self.devices.values_mut().next() {
            match device.create_directory_ipc(path).await {
                Ok(_) => AgentResponse::Success,
                Err(e) => AgentResponse::Error { 
                    message: format!("Failed to create directory: {}", e) 
                },
            }
        } else {
            AgentResponse::Error { 
                message: "No device connected".to_string() 
            }
        }
    }

    pub async fn get_metadata(&mut self, path: &str) -> AgentResponse {
        if let Some(device) = self.devices.values_mut().next() {
            match device.get_metadata_ipc(path).await {
                Ok(entry) => AgentResponse::Metadata { entry },
                Err(e) => AgentResponse::Error { 
                    message: format!("Failed to get metadata: {}", e) 
                },
            }
        } else {
            AgentResponse::Error { 
                message: "No device connected".to_string() 
            }
        }
    }
    
    // Méthode utilitaire pour debug
    pub fn list_active_devices(&self) -> Vec<String> {
        self.devices.keys().cloned().collect()
    }

    pub fn device_count(&self) -> usize {
        self.devices.len()
    }
}