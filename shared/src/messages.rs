// shared/src/messages.rs
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use std::path::PathBuf;

// =====================================
// Messages Backend ↔ Agent
// =====================================

// Messages du Backend vers l'Agent
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum BackendRequest {
    ListFiles { path: String },
    ReadFile { path: String },
    WriteFile { path: String, data: Vec<u8> },
    DeleteFile { path: String },
    CreateDirectory { path: String },
    GetMetadata { path: String },
}

// Réponses de l'Agent vers le Backend
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum AgentResponse {
    FileList { files: Vec<FileEntry> },
    FileData { data: Vec<u8> },
    Success,
    Error { message: String },
    Metadata { entry: FileEntry },
}

// Notifications spontanées de l'Agent vers le Backend
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum AgentNotification {
    DeviceConnected { device_id: String },
    DeviceDisconnected { device_id: String },
    FileChanged { path: String },
}

// =====================================
// Messages Agent ↔ Worker 
// =====================================

// Messages de l'Agent vers le Worker
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum WorkerRequest {
    MountDevice {
        device_path: PathBuf,
        device_id: String,
    },
    UnmountDevice {
        device_id: String,
    },
}

// Réponses du Worker vers l'Agent
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum WorkerResponse {
    MountSuccess {
        device_id: String,
        mount_path: PathBuf,
        filesystem_type: String,
    },
    MountError {
        device_id: String,
        error: String,
    },
    UnmountSuccess { device_id: String },
    UnmountError { device_id: String, error: String },
}

// Messages IPC filesystem entre Agent et Worker
#[derive(Serialize, Deserialize, Debug)]
pub enum IPCRequest {
    ListFiles { path: String },
    ReadFile { path: String },
    WriteFile { path: String, data: Vec<u8> },
    DeleteFile { path: String },
    CreateDirectory { path: String },
    GetMetadata { path: String },
}

#[derive(Serialize, Deserialize, Debug)]
pub enum IPCResponse {
    FileList { files: Vec<FileEntry> },
    FileData { data: Vec<u8> },
    Success,
    Error { message: String },
    Metadata { entry: FileEntry },
}

// =====================================
// Types communs
// =====================================

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FileEntry {
    pub path: String,
    pub size: u64,
    pub is_directory: bool,
    pub modified: Option<String>, // ISO 8601 timestamp
    pub etag: String, // Hash du fichier pour S3
}

// Message wrapper avec structure complète pour WebSocket
#[derive(Serialize, Deserialize, Debug)]
pub enum WebSocketMessage {
    // Requête avec ID de corrélation
    Request { 
        id: Uuid, 
        request: BackendRequest 
    },
    // Réponse avec ID de corrélation
    Response { 
        id: Uuid, 
        response: AgentResponse 
    },
    // Notification sans ID (spontanée)
    Notification(AgentNotification),
}