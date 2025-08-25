use std::path::PathBuf;
use std::collections::HashMap;
use std::process::Stdio;
use tokio::process::{Command as AsyncCommand, Child, ChildStdin, ChildStdout};
use tokio::io::{AsyncWriteExt, BufReader, AsyncBufReadExt};
use anyhow::{Context, Result};
use shared::{WorkerRequest, WorkerResponse, FileRequest, FileResponse};
use serde_json;

// Gère les opérations : prend une map de device pour gérer plusieurs périphériques
pub struct OperationManager {
    devices: HashMap<String, UsbDevice>,
}

impl OperationManager {
    pub fn new() -> Self {
        Self {
            devices: HashMap::new(),
        }
    }

    pub fn add_device(&mut self, device: UsbDevice) {
        println!("🔑 Ajout du device {} au gestionnaire", device.device_id);
        self.devices.insert(device.device_id.clone(), device);
    }

    pub async fn remove_device(&mut self, device_id: &str) {
        if let Some(mut device) = self.devices.remove(device_id) {
            println!("🧹 Nettoyage device: {}", device_id);
            let _ = device.unmount_device().await;
        } else {
            println!("⚠️ Device {} déjà nettoyé ou inexistant", device_id);
        }
    }

    pub async fn list_files(&mut self, path: &str) -> FileResponse {
        if let Some(device) = self.devices.values_mut().next() {
            match device.send_ipc_request(FileRequest::ListFiles { 
                path: path.to_string() 
            }).await {
                Ok(response) => response,
                Err(e) => FileResponse::Error { 
                    message: format!("Impossible de lister le fichier: {}", e) 
                },
            }
        } else {
            FileResponse::Error { 
                message: "Périphérique pas monté".to_string() 
            }
        }
    }

    pub async fn read_file(&mut self, path: &str) -> FileResponse {
        if let Some(device) = self.devices.values_mut().next() {
            match device.send_ipc_request(FileRequest::ReadFile { 
                path: path.to_string() 
            }).await {
                Ok(response) => response,
                Err(e) => FileResponse::Error { 
                    message: format!("Impossible de lire : {}", e) 
                },
            }
        } else {
            FileResponse::Error { 
                message: "Périphérique pas monté".to_string() 
            }
        }
    }

    pub async fn write_file(&mut self, path: &str, data: Vec<u8>) -> FileResponse {
        if path.is_empty() {
            return FileResponse::Error { 
                message: "Impossible d'écrire à la racine".to_string() 
            };
        }

        if let Some(device) = self.devices.values_mut().next() {
            match device.send_ipc_request(FileRequest::WriteFile { 
                path: path.to_string(), 
                data 
            }).await {
                Ok(response) => response,
                Err(e) => FileResponse::Error { 
                    message: format!("Impossible d'upload : {}", e) 
                },
            }
        } else {
            FileResponse::Error { 
                message: "Périphérique pas monté".to_string() 
            }
        }
    }

    pub async fn delete_file(&mut self, path: &str) -> FileResponse {
        if path.is_empty() {
            return FileResponse::Error { 
                message: "Impossible de supprimer la racine".to_string() 
            };
        }

        if let Some(device) = self.devices.values_mut().next() {
            match device.send_ipc_request(FileRequest::DeleteFile { 
                path: path.to_string() 
            }).await {
                Ok(response) => response,
                Err(e) => FileResponse::Error { 
                    message: format!("Suppression impossible: {}", e) 
                },
            }
        } else {
            FileResponse::Error { 
                message: "Périphérique pas monté".to_string() 
            }
        }
    }

    pub async fn create_directory(&mut self, path: &str) -> FileResponse {
        if path.is_empty() {
            return FileResponse::Error { 
                message: "Création de répertoire impossible à la racine".to_string() 
            };
        }

        if let Some(device) = self.devices.values_mut().next() {
            match device.send_ipc_request(FileRequest::CreateDirectory { 
                path: path.to_string() 
            }).await {
                Ok(response) => response,
                Err(e) => FileResponse::Error { 
                    message: format!("Erreur dans la création du répertoire: {}", e) 
                },
            }
        } else {
            FileResponse::Error { 
                message: "Périphérique pas monté".to_string() 
            }
        }
    }

    pub async fn get_metadata(&mut self, path: &str) -> FileResponse {
        if let Some(device) = self.devices.values_mut().next() {
            match device.send_ipc_request(FileRequest::GetMetadata { 
                path: path.to_string() 
            }).await {
                Ok(response) => response,
                Err(e) => FileResponse::Error { 
                    message: format!("Impossible de réccupérer les métadonées: {}", e) 
                },
            }
        } else {
            FileResponse::Error { 
                message: "Périphérique pas monté".to_string() 
            }
        }
    }

    pub fn list_active_devices(&self) -> Vec<String> {
        self.devices.keys().cloned().collect()
    }

    pub fn device_count(&self) -> usize {
        self.devices.len()
    }
}

// Pour récupérer les infos d'un périphérique et les communiquer au worker par ipc
#[derive(Debug)]
pub struct UsbDevice {
    pub device_id: String,
    pub device_path: PathBuf,
    pub filesystem_type: String,
    pub mount_path: PathBuf,
    
    // On communique avec le worker en pipe stdout/stdin
    worker_stdin: Option<ChildStdin>,
    worker_stdout: Option<BufReader<ChildStdout>>,
    worker_process: Option<Child>,
}

impl UsbDevice {
    pub fn new(device_id: String, device_path: PathBuf) -> Self {
        Self {
            device_id,
            device_path,
            filesystem_type: String::new(),
            mount_path: PathBuf::new(),
            worker_stdin: None,
            worker_stdout: None,
            worker_process: None,
        }
    }

    pub async fn mount_device(&mut self) -> Result<()> {
        let request = WorkerRequest::MountDevice {
            device_path: self.device_path.clone(),
            device_id: self.device_id.clone(),
        };
        
        let request_json = serde_json::to_string(&request)?;
        
        // On lance le worker avec pipes
        let mut child = AsyncCommand::new("/usr/local/bin/rustykey-worker")
            .arg("--request")
            .arg(&request_json)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Le lancement du worker a échoué")?;
        
        // On récupère les pipes
        let stdout = child.stdout.take().unwrap();
        let stdin = child.stdin.take().unwrap();
        
        let mut reader = BufReader::new(stdout);
        let mut response_line = String::new();
        
        let n = reader.read_line(&mut response_line).await
            .context("Réponse du worker impossible à lire")?;
        
        eprintln!("🛠 Agent: Réponse montage reçue ({} bytes): '{}'", n, response_line.trim());
        
        let response: WorkerResponse = serde_json::from_str(response_line.trim())
            .context("Impossible de parser la réponse du worker")?;
        
        match response {
            WorkerResponse::MountSuccess { mount_path, filesystem_type, .. } => {
                self.mount_path = mount_path;
                self.filesystem_type = filesystem_type;
                
                self.worker_stdin = Some(stdin);
                self.worker_stdout = Some(reader); // Récupère le stdout du reader
                self.worker_process = Some(child);
                
                Ok(())
            }
            WorkerResponse::MountError { error, .. } => {
                Err(anyhow::anyhow!("Erreur de montage: {}", error))
            }
            _ => Err(anyhow::anyhow!("Erreur réponse du worker inconnue"))
        }
    }

    pub async fn send_ipc_request(&mut self, request: FileRequest) -> Result<FileResponse> {
        let stdin = self.worker_stdin.as_mut()
            .ok_or_else(|| anyhow::anyhow!("Worker pas lancé"))?;
        let stdout = self.worker_stdout.as_mut()
            .ok_or_else(|| anyhow::anyhow!("Worker pas lancé"))?;

        // On envoie la requête en une ligne json au stdin
        let request_json = serde_json::to_string(&request)?;
        eprintln!("🛠 Agent: Envoi requête IPC: {}", request_json);
        
        stdin.write_all(request_json.as_bytes()).await?;
        stdin.write_all(b"\n").await?; // Délimiteur de ligne
        stdin.flush().await?;
        eprintln!("🛠 Agent: Requête envoyée");

        // On lit ligne par ligne la réponse
        let mut response_line = String::new();
        
        eprintln!("🛠 Agent: Attente réponse...");
        let n = stdout.read_line(&mut response_line).await?;
        eprintln!("🛠 Agent: Reçu {} bytes: '{}'", n, response_line.trim());
        
        if n == 0 {
            return Err(anyhow::anyhow!("Worker pas lancé"));
        }
        
        let response: FileResponse = serde_json::from_str(response_line.trim())?;
        eprintln!("🛠 Agent: Réponse : {:?}", response);
        
        Ok(response)
    }

    pub async fn unmount_device(&mut self) -> Result<()> {
        // On ferme les pipes et tuer le worker
        if let Some(mut child) = self.worker_process.take() {
            let _ = child.kill().await;
        }
        
        self.worker_stdin = None;
        self.worker_stdout = None;
        
        Ok(())
    }
}