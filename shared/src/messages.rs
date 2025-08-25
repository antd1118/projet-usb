use serde::{Serialize, Deserialize};
use uuid::Uuid;
use std::path::PathBuf;

// Pour les opérations de fichier (Backend=>Agent et Agent=>Worker)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum FileRequest {
    ListFiles { path: String },
    ReadFile { path: String },
    WriteFile { path: String, data: Vec<u8> },
    DeleteFile { path: String },
    CreateDirectory { path: String },
    GetMetadata { path: String },
}

// Pour les réponses (Agent=>Backend et Worker=>Agent)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum FileResponse {
    FileList { files: Vec<FileEntry> },
    FileData { data: Vec<u8> },
    Success,
    Error { message: String },
    Metadata { entry: FileEntry },
}



// Messages de montage de l'Agent vers le Worker
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



// Notifications de statut du device de l'Agent vers le Backend
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum AgentNotification {
    DeviceConnected { device_id: String },
    DeviceDisconnected { device_id: String },
    FileChanged { path: String },
}



#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FileEntry {
    pub path: String,
    pub size: u64,
    pub is_directory: bool,
    pub modified: Option<String>,
    pub etag: String, // todo
}

#[derive(Serialize, Deserialize, Debug)]
pub enum WebSocketMessage {

    Request {
        id: Uuid,
        request: FileRequest
    },

    Response {
        id: Uuid,
        response: FileResponse
    },

    Notification(AgentNotification),
}