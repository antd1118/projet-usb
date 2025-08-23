use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{StatusCode},
    response::Response,
    routing::{get, put, delete, head},
    Router,
};
use std::collections::HashMap;
use std::hash::{Hasher, DefaultHasher};
use tokio::sync::{RwLock, mpsc, oneshot};
use std::sync::Arc;
use uuid::Uuid;
use shared::{AgentResponse, BackendRequest};
use chrono::{DateTime, Utc};

// Service principal qui gère tous les agents connectés et leurs requêtes/réponses
#[derive(Clone)]
pub struct RustyKeyS3Service {

    // Map pour envoyer les requêtes S3 à l'agent via un cannal, pour chaque device branché
    agents: Arc<RwLock<HashMap<String, mpsc::UnboundedSender<(Uuid, BackendRequest)>>>>,
    // UnboundedSender peut gérer un flux de requêtes

    // Map pour recevoir la réponse à la requête identifiée par uuid
    pending_responses: Arc<RwLock<HashMap<Uuid, oneshot::Sender<AgentResponse>>>>,
    // oneshot::Sender cible la réponse unique liée à la requête
}

impl RustyKeyS3Service {

    pub fn new() -> Self {
        Self {
            agents: Arc::new(RwLock::new(HashMap::new())),
            pending_responses: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn register_agent(&self, device_id: String, sender: mpsc::UnboundedSender<(Uuid, BackendRequest)>) {
        let bucket_name = format!("rustykey-{}", device_id);
        println!("📱 Enregistrement agent device_id: {} -> bucket: {}", device_id, bucket_name);
        
        // On ajoute directement le sender à la map des agents actifs
        self.agents.write().await.insert(bucket_name, sender);
    }

    pub async fn unregister_agent(&self, device_id: &str) {
        let bucket_name = format!("rustykey-{}", device_id);
        self.agents.write().await.remove(&bucket_name);
        println!("📱 Désenregistrement agent device_id: {} -> bucket: {}", device_id, bucket_name);
    }

    // Traite une réponse d'agent qui sera recue dans la fonction d'apres
    pub async fn handle_agent_response(&self, request_id: Uuid, response: AgentResponse) {
        // On essaye de retirer le cannal correspondant à la requête
        if let Some(sender) = self.pending_responses.write().await.remove(&request_id) {
            // Si ca marche, on envoie la réponse au cannal oneshot qui attendait
            let _ = sender.send(response);
        } else {
            println!("⚠️ Réponse reçue pour requête inconnue: {}", request_id);
        }
    }

    // Envoie une requête à un agent et attend la réponse
    async fn send_to_agent(&self, bucket: &str, request: BackendRequest) -> Result<AgentResponse, String> {
        let agents = self.agents.read().await;
        
        // On vérifie que l'agent est dans la map (clé branchée)
        if let Some(agent_sender) = agents.get(bucket) {
            // On génère un nouvel UUID pour la requête
            let request_id = Uuid::new_v4();
            // On crée le canal oneshot pour la réponse
            let (tx, rx) = oneshot::channel();
            
            // On renregistre le cannal dans la map des réponses en attente avec l'uuid
            self.pending_responses.write().await.insert(request_id, tx);
            
            // On envoie la requête avec l'uuid à l'agent 
            if agent_sender.send((request_id, request)).is_err() {
                let _ = self.pending_responses.write().await.remove(&request_id);
                return Err("Clé débranchée".to_string());
            }
            
            // Et on attend la réponse
            match tokio::time::timeout(std::time::Duration::from_secs(30), rx).await {
                Ok(Ok(response)) => Ok(response),
                Ok(Err(_)) => Err("Cannal de réponse fermé".to_string()),
                Err(_) => {
                    let _ = self.pending_responses.write().await.remove(&request_id);
                    Err("Agent response timeout".to_string())
                }
            }
        } else {
            Err(format!("Clé pas detectée pour ce bucket: {}", bucket))
        }
    }

    pub fn create_router(self) -> Router {
        Router::new()
            .route("/", get(list_buckets))
            
            .route("/{bucket}", get(list_objects))
            .route("/{bucket}/", get(list_objects))
            .route("/{bucket}", head(head_bucket))
            .route("/{bucket}/", head(head_bucket))
            
            .route("/{bucket}/{*key}", get(get_object))
            .route("/{bucket}/{*key}", put(put_object))
            .route("/{bucket}/{*key}", delete(delete_object))
            .route("/{bucket}/{*key}", head(head_object))
            
            .with_state(self)
    }
}


async fn list_buckets(State(service): State<RustyKeyS3Service>) -> Result<Response<Body>, StatusCode> {
    println!("📋 ListBuckets appelé");
    // On lit tous les agents (1 agent = 1 périphérique)
    let agents = service.agents.read().await;
    let current_date = chrono::Utc::now().to_rfc3339();
    // On crée un élément XML pour les contenir
    let buckets: Vec<String> = agents.keys().map(|name| {
        format!(
            "<Bucket>
            <Name>{}</Name>
            <CreationDate>{}</CreationDate>
            </Bucket>"
            , name, current_date
        )
    }).collect();

    // Format d'XML pour S3
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
        <ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
            <Owner>
                <ID>rustykey</ID>
                <DisplayName>RustyKey</DisplayName>
            </Owner>
            <Buckets>
                {}
            </Buckets>
        </ListAllMyBucketsResult>"#,
        buckets.join("")
    );
    
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/xml")
        .header("Server", "RustyKey/1.0")
        .body(Body::from(xml))
        .unwrap())
}


// Liste contenu du bucket
async fn list_objects(
    Path(bucket): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    State(service): State<RustyKeyS3Service>
) -> Result<Response<Body>, StatusCode> {

    // On récupère le prefix (nom du dossier à lister)
    let path = query.get("prefix").cloned().unwrap_or_default();
    println!("📋 ListObjects pour bucket: {} avec prefix: '{}'", bucket, path);

    let delimiter = "/"; 
    let max_keys = 1000; // Nombre max d'objets renvoyés

    // On envoie la requête à l'agent pour qu'il liste le répertoire
    match service.send_to_agent(&bucket, BackendRequest::ListFiles { path: path.clone() }).await {
        Ok(AgentResponse::FileList { files }) => {
            let mut contents = Vec::new(); // Pour stocker els XML de fichiers
            let mut common_prefixes = Vec::new(); // Pour stocker les XML de dossiers

            // On parcourt chaques fichiers et dossiers récupérés
            // Et on construit la clé avec le chemin complet
            for file in files.into_iter().take(max_keys) {
                let key = if path.is_empty() {
                    file.path.clone()
                } else {
                    format!("{}/{}", path.trim_end_matches('/'), file.path)
                };

                if file.is_directory {
                    let prefix = format!("{}/", key);
                    common_prefixes.push(format!( // On utilise CommonPrefix pour les dossiers
                        "<CommonPrefixes>
                        <Prefix>{}</Prefix>
                        </CommonPrefixes>",
                        prefix
                    ));
                } else {
                    // Pour fichiers
                    contents.push(create_object_xml(&key, &file, false));
                }
            }

            let xml = format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
                <ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                    <Name>{}</Name>
                    <Prefix>{}</Prefix>
                    <Delimiter>{}</Delimiter>
                    <KeyCount>{}</KeyCount>
                    <MaxKeys>{}</MaxKeys>
                    <IsTruncated>false</IsTruncated>
                    {}{}
                </ListBucketResult>"#,
                bucket, path, delimiter,
                contents.len() + common_prefixes.len(), max_keys,
                contents.join(""), common_prefixes.join("")
            );

            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/xml")
                .header("Server", "RustyKey/1.0")
                .body(Body::from(xml))
                .unwrap())
        }
        Ok(AgentResponse::Error { message }) => {
            println!("❌ Erreur listing bucket {}: {}", bucket, message);
            if message.contains("No device connected") {
                Err(StatusCode::NOT_FOUND)
            } else {
                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
        _ => {
            println!("❌ Réponse inattendue pour listing bucket {}", bucket);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}


// Télécharge un fichier
async fn get_object(
    Path((bucket, key)): Path<(String, String)>,
    State(service): State<RustyKeyS3Service>
) -> Result<Response<Body>, StatusCode> {
    println!("📥 GetObject - bucket: {}, key: {}", bucket, key);

    // On demande à l'agent les métadonnées du fichier voulu (date modif etc)
    let metadata = service
        .send_to_agent(&bucket, BackendRequest::GetMetadata { path: key.clone() })
        .await;

    match metadata {
        Ok(AgentResponse::Metadata { entry }) => {
            // On demande à l'agent de lire le fichier
            match service
                .send_to_agent(&bucket, BackendRequest::ReadFile { path: key.clone() })
                .await
            {
                Ok(AgentResponse::FileData { data }) => {
                    let mut response = Response::builder()
                        .status(StatusCode::OK)
                        .header("Content-Type", "application/octet-stream")
                        .header("Content-Length", data.len())
                        .header("Server", "RustyKey/1.0");

                    // On ajoute des headers S3
                    if let Some(modified) = entry.modified.as_ref().and_then(|s| to_rfc1123(s)) {
                        response = response.header("Last-Modified", modified);
                    }
                    
                    if !entry.etag.is_empty() {
                        response = response.header("ETag", format!("\"{}\"", entry.etag));
                    } else {
                        response = response.header("ETag", format!("\"{}\"", md5_hash(&data)));
                    }

                    Ok(response.body(Body::from(data)).unwrap())
                }
                Ok(AgentResponse::Error { message }) => {
                    println!("❌ Erreur lecture fichier {}/{}: {}", bucket, &key, message);
                    Err(StatusCode::NOT_FOUND)
                }
                _ => {
                    println!("❌ Réponse inattendue pour lecture fichier {}/{}", bucket, &key);
                    Err(StatusCode::INTERNAL_SERVER_ERROR)
                }
            }
        }
        Ok(AgentResponse::Error { message }) => {
            println!("❌ Erreur métadonnées {}/{}: {}", bucket, &key, message);
            Err(StatusCode::NOT_FOUND)
        }
        _ => {
            println!("❌ Réponse inattendue pour métadonnées {}/{}", bucket, &key);
            Err(StatusCode::NOT_FOUND)
        }
    }
}


// Upload un fichier en créant dossier si besoin
async fn put_object(
    Path((bucket, key)): Path<(String, String)>,
    State(service): State<RustyKeyS3Service>,
    body: Body,
) -> Result<Response<Body>, StatusCode> {
    println!("📤 PutObject - bucket: {}, key: {}", bucket, key);
    
    // On lit le contenu
    let data = match axum::body::to_bytes(body, usize::MAX).await {
        Ok(bytes) => bytes.to_vec(),
        Err(e) => {
            println!("❌ Erreur lecture corps requête: {}", e);
            return Err(StatusCode::BAD_REQUEST);
        }
    };

    // Si key se termine par '/', on fait une création de dossier
    if key.ends_with('/') {
        let dir_path = key.trim_end_matches('/').to_string();
        match service.send_to_agent(&bucket, BackendRequest::CreateDirectory { path: dir_path }).await {
            Ok(AgentResponse::Success) => {
                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header("Server", "RustyKey/1.0")
                    .header("ETag", format!("\"{}\"", md5_hash(&[])))
                    .body(Body::empty())
                    .unwrap())
            }
            Ok(AgentResponse::Error { message }) => {
                println!("❌ Erreur création dossier {}/{}: {}", bucket, &key, message);
                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
            _ => {
                println!("❌ Réponse inattendue pour création dossier {}/{}", bucket, &key);
                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
    } else {
        // Sinon, on crée le fichier
        match service.send_to_agent(&bucket, BackendRequest::WriteFile { path: key.clone(), data: data.clone() }).await {
            Ok(AgentResponse::Success) => {
                let etag = md5_hash(&data);
                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header("Server", "RustyKey/1.0")
                    .header("ETag", format!("\"{}\"", etag))
                    .body(Body::empty())
                    .unwrap())
            }
            Ok(AgentResponse::Error { message }) => {
                println!("❌ Erreur écriture fichier {}/{}: {}", bucket, &key, message);
                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
            _ => {
                println!("❌ Réponse inattendue pour écriture fichier {}/{}", bucket, &key);
                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
    }
}


// Supprime un fichier ou dossier
async fn delete_object(
    Path((bucket, key)): Path<(String, String)>,
    State(service): State<RustyKeyS3Service>,
) -> Result<Response<Body>, StatusCode> {
    println!("🗑️ DeleteObject - bucket: {}, key: {}", bucket, key);
    
    match service.send_to_agent(&bucket, BackendRequest::DeleteFile { path: key.clone() }).await {
        Ok(AgentResponse::Success) => {
            Ok(Response::builder()
                .status(StatusCode::NO_CONTENT)
                .header("Server", "RustyKey/1.0")
                .body(Body::empty())
                .unwrap())
        }
        Ok(AgentResponse::Error { message }) => {
            println!("❌ Erreur suppression {}/{}: {}", bucket, key, message);
            // S3 retourne 204 même si l'objet n'existe pas
            if message.contains("not found") || message.contains("No such file") {
                Ok(Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .header("Server", "RustyKey/1.0")
                    .body(Body::empty())
                    .unwrap())
            } else {
                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
        _ => {
            println!("❌ Réponse inattendue pour suppression {}/{}", bucket, key);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// Vérifie si un bucket existe
async fn head_bucket(
    Path(bucket): Path<String>,
    State(service): State<RustyKeyS3Service>
) -> Result<Response<Body>, StatusCode> {
    println!("🔍 HeadBucket - bucket: {}", bucket);
    
    let agents = service.agents.read().await;
    if agents.contains_key(&bucket) {
        Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Server", "RustyKey/1.0")
            .body(Body::empty())
            .unwrap())
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

// Récupère métadonnées sans contenu
async fn head_object(
    Path((bucket, key)): Path<(String, String)>,
    State(service): State<RustyKeyS3Service>
) -> Result<Response<Body>, StatusCode> {
    println!("🔍 HeadObject - bucket: {}, key: {}", bucket, key);

    match service
        .send_to_agent(&bucket, BackendRequest::GetMetadata { path: key.clone() })
        .await
    {
        Ok(AgentResponse::Metadata { entry }) => {
            let mut response = Response::builder()
                .status(StatusCode::OK)
                .header("Content-Length", entry.size)
                .header("Server", "RustyKey/1.0");

            if let Some(modified) = entry.modified.as_ref().and_then(|s| to_rfc1123(s)) {
                response = response.header("Last-Modified", modified);
            }
            
            if !entry.etag.is_empty() {
                response = response.header("ETag", format!("\"{}\"", entry.etag));
            }

            Ok(response.body(Body::empty()).unwrap())
        }
        Ok(AgentResponse::Error { .. }) => Err(StatusCode::NOT_FOUND),
        _ => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}


// Convertit les métadonnées fichier en XML S3 <Contents>
fn create_object_xml(key: &str, file: &shared::FileEntry, is_dir: bool) -> String {
    let last_modified = file
        .modified
        .as_ref()
        .and_then(|s| to_rfc1123(s))
        .unwrap_or_else(|| "Thu, 01 Jan 1970 00:00:00 GMT".to_string());

    let etag = if file.etag.is_empty() {
        "d41d8cd98f00b204e9800998ecf8427e".to_string() // MD5 vide par défaut
    } else {
        file.etag.clone()
    };

    let size = if is_dir { 0 } else { file.size };

    format!(
        "<Contents>\
            <Key>{}</Key>\
            <Size>{}</Size>\
            <LastModified>{}</LastModified>\
            <ETag>\"{}\"</ETag>\
            <StorageClass>STANDARD</StorageClass>\
        </Contents>",
        xml_escape(key), size, last_modified, etag
    )
}

/// Convertit timestamp RFC3339 en format RFC1123 requis par S3
fn to_rfc1123(date: &str) -> Option<String> {
    DateTime::parse_from_rfc3339(date)
        .ok()
        .map(|dt| dt.with_timezone(&Utc).format("%a, %d %b %Y %H:%M:%S GMT").to_string())
}

/// Échappement XML pour éviter les injection
fn xml_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

// Génération ETag (hash des données)
fn md5_hash(data: &[u8]) -> String {
    let mut hasher = DefaultHasher::new();
    hasher.write(data);
    format!("{:x}", hasher.finish())
}