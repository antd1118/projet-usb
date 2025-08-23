use axum::extract::ws::{WebSocket, Message};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use uuid::Uuid;

use shared::{WebSocketMessage, BackendRequest, AgentNotification};
use crate::expose_s3::RustyKeyS3Service;

pub async fn handle_agent_connection(socket: WebSocket, s3_service: RustyKeyS3Service) {
    println!("📱 Nouvelle connexion agent WebSocket");
    
    let (mut ws_sender, mut ws_receiver) = socket.split();
    
    // Cannal pour envoyer plusieurs messages à l'agent entre threads 
    let (outbound_tx, mut outbound_rx) = mpsc::unbounded_channel::<Message>();
    
    let mut device_id: Option<String> = None;

    // On envoie les messages à l'agent
    // On lit le canal receiver outbound_rx et envoie les messages un par un sur la connexion websocket avec ws_sender
    let task1: tokio::task::JoinHandle<()> = tokio::spawn(async move {
        while let Some(message) = outbound_rx.recv().await {
            if ws_sender.send(message).await.is_err() {
                println!("❌ Erreur envoi WebSocket vers agent");
                break;
            }
        }
        println!("📤 Task envoi WebSocket terminée");
    });

    // On clone le sender pour l'utiliser dans le service S3 pour les requetes
    let outbound_tx_clone = outbound_tx.clone();
    
    // Boucle de récéption des messages de l'agent
    while let Some(msg) = ws_receiver.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                println!("📨 Message reçu de l'agent : {}", text);
                
                // On le parse
                match serde_json::from_str::<WebSocketMessage>(&text) {
                    Ok(WebSocketMessage::Notification(AgentNotification::DeviceConnected { device_id: dev_id })) => {
                        println!("🔌 Device connecté: {}", dev_id);
                        // Si le device est branché, on recup son id
                        device_id = Some(dev_id.clone());
                        
                        // On enregistre l'agent dans le service S3 avec avec son cannal de requete
                        let request_sender = create_request_sender(outbound_tx_clone.clone());
                        s3_service.register_agent(dev_id.clone(), request_sender).await;
                    }
                    Ok(WebSocketMessage::Notification(AgentNotification::DeviceDisconnected { device_id: dev_id })) => {
                        println!("🔌 Device déconnecté: {}", dev_id);
                        
                        // On le supprime de la map et du service
                        s3_service.unregister_agent(&dev_id).await;
                    }
                    Ok(WebSocketMessage::Notification(AgentNotification::FileChanged { path })) => {
                        println!("📁 Changement de fichier détecté: {}", path);
                        // todo
                    }
                    Ok(WebSocketMessage::Response { id, response }) => {
                        println!("📥 Réponse reçue pour requête {} : {:?}", id, response);
                        
                        // Transmet la réponse au service S3
                        s3_service.handle_agent_response(id, response).await;
                    }
                    Ok(WebSocketMessage::Request { .. }) => {
                        println!("⚠️ Requête inattendue de l'agent (normalement c'est l'inverse)");
                    }
                    Err(e) => {
                        println!("❌ Erreur parsing JSON : {}", e);
                    }
                }
            }
            Ok(Message::Close(_)) => {
                println!("📱 Connexion agent fermée");
                break;
            }
            Err(e) => {
                println!("❌ Erreur WebSocket : {}", e);
                break;
            }
            _ => {

            }
        }
    }

    // On nettoie à la déconnexion
    task1.abort();
    
    if let Some(dev_id) = device_id {
        s3_service.unregister_agent(&dev_id).await;
        println!("🧹 Agent {} nettoyé", dev_id);
    }
    
    println!("📱 Fin de handle_agent_connection");
}

// Pour convertir les requêtes en messages WebSocket
fn create_request_sender(
    outbound_tx: mpsc::UnboundedSender<Message>
) -> mpsc::UnboundedSender<(Uuid, BackendRequest)> {
    let (request_tx, mut request_rx) = mpsc::unbounded_channel::<(Uuid, BackendRequest)>();
    
    tokio::spawn(async move {
        while let Some((request_id, request)) = request_rx.recv().await {
            println!("📤 Envoi d'une requête vers l'agent");
            
            let message = WebSocketMessage::Request {
                id: request_id,
                request,
            };
            
            if let Ok(json) = serde_json::to_string(&message) {
                // Conversion string en bytes
                let ws_message = Message::Text(json.into());
                if outbound_tx.send(ws_message).is_err() {
                    println!("❌ Impossible d'envoyer la requête vers l'agent");
                    break;
                }
            } else {
                println!("❌ Erreur sérialisation requête");
            }
        }
        println!("📤 Request sender task terminée");
    });
    
    request_tx
}