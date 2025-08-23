use std::path::PathBuf;
use std::process::Stdio;
use tokio::process::{Command as AsyncCommand, Child, ChildStdin, ChildStdout};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, AsyncBufReadExt};
use anyhow::{Context, Result};
use shared::{WorkerRequest, WorkerResponse, IPCRequest, IPCResponse, FileEntry};
use serde_json;

#[derive(Debug)]
pub struct UsbDevice {
    pub device_id: String,
    pub device_path: PathBuf,
    pub filesystem_type: String,
    pub mount_path: PathBuf,
    
    // On communique avec le worker en stdout/stdin
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
        
        // Lancer le worker avec pipes
        let mut child = AsyncCommand::new("/usr/local/bin/rustykey-worker")
            .arg("--request")
            .arg(&request_json)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to launch worker")?;
        
        // Récupérer les pipes
        let stdout = child.stdout.take().unwrap();
        let stdin = child.stdin.take().unwrap();
        
        let mut reader = BufReader::new(stdout);
        let mut response_line = String::new();
        
        let n = reader.read_line(&mut response_line).await
            .context("Failed to read worker response")?;
        
        eprintln!("🐛 Agent: Réponse montage reçue ({} bytes): '{}'", n, response_line.trim());
        
        let response: WorkerResponse = serde_json::from_str(response_line.trim())
            .context("Failed to parse worker response")?;
        
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
                Err(anyhow::anyhow!("Mount error: {}", error))
            }
            _ => Err(anyhow::anyhow!("Unexpected worker response"))
        }
    }

    pub async fn list_files_ipc(&mut self, relative_path: &str) -> Result<Vec<FileEntry>> {
        let request = IPCRequest::ListFiles { path: relative_path.to_string() };
        let response = self.send_ipc_request(request).await?;
        
        match response {
            IPCResponse::FileList { files } => Ok(files),
            IPCResponse::Error { message } => Err(anyhow::anyhow!(message)),
            _ => Err(anyhow::anyhow!("Unexpected IPC response")),
        }
    }

    pub async fn read_file_ipc(&mut self, relative_path: &str) -> Result<Vec<u8>> {
        let request = IPCRequest::ReadFile { path: relative_path.to_string() };
        let response = self.send_ipc_request(request).await?;
        
        match response {
            IPCResponse::FileData { data } => Ok(data),
            IPCResponse::Error { message } => Err(anyhow::anyhow!(message)),
            _ => Err(anyhow::anyhow!("Unexpected IPC response")),
        }
    }

    pub async fn write_file_ipc(&mut self, relative_path: &str, data: Vec<u8>) -> Result<()> {
        let request = IPCRequest::WriteFile { path: relative_path.to_string(), data };
        let response = self.send_ipc_request(request).await?;
        
        match response {
            IPCResponse::Success => Ok(()),
            IPCResponse::Error { message } => Err(anyhow::anyhow!(message)),
            _ => Err(anyhow::anyhow!("Unexpected IPC response")),
        }
    }

    pub async fn delete_file_ipc(&mut self, relative_path: &str) -> Result<()> {
        let request = IPCRequest::DeleteFile { path: relative_path.to_string() };
        let response = self.send_ipc_request(request).await?;
        
        match response {
            IPCResponse::Success => Ok(()),
            IPCResponse::Error { message } => Err(anyhow::anyhow!(message)),
            _ => Err(anyhow::anyhow!("Unexpected IPC response")),
        }
    }

    pub async fn create_directory_ipc(&mut self, relative_path: &str) -> Result<()> {
        let request = IPCRequest::CreateDirectory { path: relative_path.to_string() };
        let response = self.send_ipc_request(request).await?;
        
        match response {
            IPCResponse::Success => Ok(()),
            IPCResponse::Error { message } => Err(anyhow::anyhow!(message)),
            _ => Err(anyhow::anyhow!("Unexpected IPC response")),
        }
    }

    pub async fn get_metadata_ipc(&mut self, relative_path: &str) -> Result<FileEntry> {
        let request = IPCRequest::GetMetadata { path: relative_path.to_string() };
        let response = self.send_ipc_request(request).await?;
        
        match response {
            IPCResponse::Metadata { entry } => Ok(entry),
            IPCResponse::Error { message } => Err(anyhow::anyhow!(message)),
            _ => Err(anyhow::anyhow!("Unexpected IPC response")),
        }
    }

    async fn send_ipc_request(&mut self, request: IPCRequest) -> Result<IPCResponse> {
        let stdin = self.worker_stdin.as_mut()
            .ok_or_else(|| anyhow::anyhow!("Worker not available"))?;
        let stdout = self.worker_stdout.as_mut()
            .ok_or_else(|| anyhow::anyhow!("Worker not available"))?;

        // Envoyer la requête (une ligne JSON)
        let request_json = serde_json::to_string(&request)?;
        eprintln!("🐛 Agent: Envoi requête IPC: {}", request_json);
        
        stdin.write_all(request_json.as_bytes()).await?;
        stdin.write_all(b"\n").await?; // Délimiteur de ligne
        stdin.flush().await?;
        eprintln!("🐛 Agent: Requête envoyée");

        let mut response_line = String::new();
        
        eprintln!("🐛 Agent: Attente réponse...");
        let n = stdout.read_line(&mut response_line).await?;
        eprintln!("🐛 Agent: Reçu {} bytes: '{}'", n, response_line.trim());
        
        if n == 0 {
            return Err(anyhow::anyhow!("Worker disconnected"));
        }
        
        let response: IPCResponse = serde_json::from_str(response_line.trim())?;
        eprintln!("🐛 Agent: Réponse parsée: {:?}", response);
        
        Ok(response)
    }

    pub fn get_full_path(&self, relative_path: &str) -> PathBuf {
        if relative_path.is_empty() {
            self.mount_path.clone()
        } else {
            self.mount_path.join(relative_path.trim_start_matches('/'))
        }
    }

    pub async fn unmount_device(&mut self) -> Result<()> {
        // Fermer les pipes et tuer le worker
        if let Some(mut child) = self.worker_process.take() {
            let _ = child.kill().await;
        }
        
        self.worker_stdin = None;
        self.worker_stdout = None;
        
        Ok(())
    }
}