use tokio_tungstenite::{connect_async_tls_with_config, tungstenite::Message, Connector};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::{mpsc, RwLock};
use std::sync::Arc;
use uuid::Uuid;
use anyhow::{Result, Context};

use shared::{WebSocketMessage, FileRequest, FileResponse, AgentNotification, build_client_mtls_config};
use crate::device_manager::{UsbDevice, OperationManager};
use crate::udev_monitor;

pub struct RustykeyAgent {
    device_manager: Arc<RwLock<OperationManager>>,
    notification_tx: mpsc::UnboundedSender<AgentNotification>,
    device_tx: mpsc::UnboundedSender<UsbDevice>,
}

impl RustykeyAgent {
    pub async fn new() -> Result<Self> {
        let (notification_tx, notification_rx) = mpsc::unbounded_channel();
        let (device_tx, device_rx) = mpsc::unbounded_channel();

        let device_manager = Arc::new(RwLock::new(OperationManager::new()));
        
        // Démarrer la connexion WebSocket
        Self::start_websocket(notification_rx, device_manager.clone());

        // Démarrer le gestionnaire de devices
        Self::start_device_handler(device_rx, device_manager.clone(), notification_tx.clone());

        let agent = Self {
            device_manager,
            notification_tx,
            device_tx,
        };

        Ok(agent)
    }

    pub async fn run(&mut self) -> Result<()> {
        println!("🚀 Agent RustyKey démarré");

        udev_monitor::monitor_usb_devices(
            self.device_tx.clone(),
            self.notification_tx.clone(),
        ).await?;

        Ok(())
    }

    fn start_websocket(
        notification_rx: mpsc::UnboundedReceiver<AgentNotification>,
        device_manager: Arc<RwLock<OperationManager>>,
    ) {
        tokio::spawn(async move {
            Self::websocket_task(notification_rx, device_manager).await;
        });
    }

    fn start_device_handler(
        device_rx: mpsc::UnboundedReceiver<UsbDevice>,
        device_manager: Arc<RwLock<OperationManager>>,
        notification_tx: mpsc::UnboundedSender<AgentNotification>,
    ) {
        tokio::spawn(async move {
            Self::device_handler(device_rx, device_manager, notification_tx).await;
        });
    }

    async fn websocket_task(
        notification_rx: mpsc::UnboundedReceiver<AgentNotification>,
        device_manager: Arc<RwLock<OperationManager>>,
    ) {
        
        let (broadcast_tx, _) = tokio::sync::broadcast::channel::<AgentNotification>(100);
        
        // Task qui lit notification_rx UNE SEULE FOIS et redistribue
        let mut original_rx = notification_rx;
        let broadcast_tx_clone = broadcast_tx.clone();
        tokio::spawn(async move {
            while let Some(notification) = original_rx.recv().await {
                let _ = broadcast_tx_clone.send(notification);
            }
        });

        loop {
            match Self::connect_to_backend_static().await {
                Ok((mut ws_sender, mut ws_receiver)) => {
                    println!("🌐 Connecté au backend via WebSocket mTLS");

                    let (outbound_tx, mut outbound_rx) = mpsc::unbounded_channel::<Message>();
                    let (request_tx, mut request_rx) = mpsc::unbounded_channel::<(Uuid, FileRequest)>();

                    // TASK 1 TRAITEMENT DES REQUETES BACKEND
                    let device_manager_clone = device_manager.clone();
                    let outbound_tx_clone = outbound_tx.clone();
                    let task1 = tokio::spawn(async move {
                        while let Some((request_id, request)) = request_rx.recv().await {
                            println!("🔄 Traitement requête {} : {:?}", request_id, request);
                            
                            let response = Self::handle_backend_request(&device_manager_clone, request).await;
                            
                            let msg = WebSocketMessage::Response { id: request_id, response };
                            if let Ok(json) = serde_json::to_string(&msg) {
                                let message = Message::Text(json.into());
                                if outbound_tx_clone.send(message).is_err() {
                                    println!("❌ Impossible d'envoyer la réponse");
                                    break;
                                }
                            } else {
                                println!("❌ Erreur sérialisation réponse");
                            }
                        }
                        println!("🔥 Task request handler terminée");
                    });

                    // TASK 2 GESTION DES NOTIFICATIONS
                    let outbound_tx_clone = outbound_tx.clone();
                    let device_manager_cleanup = device_manager.clone();
                    let mut local_notification_rx = broadcast_tx.subscribe();
                    let task2 = tokio::spawn(async move {
                        while let Ok(notification) = local_notification_rx.recv().await {
                            println!("📢 Envoi notification : {:?}", notification);
                            
                            // Si on recoit la notif de deco de udev_monitor, on ferme le worker avec remove_device
                            if let AgentNotification::DeviceDisconnected { ref device_id } = notification {
                                println!("🗑️ Nettoyage local device: {}", device_id);
                                device_manager_cleanup.write().await.remove_device(device_id).await;
                                println!("🧹 Device {} nettoyé localement", device_id);
                            }

                            let msg = WebSocketMessage::Notification(notification);
                            if let Ok(json) = serde_json::to_string(&msg) {
                                let message = Message::Text(json.into());
                                if outbound_tx_clone.send(message).is_err() {
                                    println!("❌ Impossible d'envoyer la notification");
                                    break;
                                }
                            } else {
                                println!("❌ Erreur sérialisation notification");
                            }
                        }
                        println!("📢 Task notification terminée");
                    });

                    // TASK 3 ENVOI WEBSOCKET
                    let task3 = tokio::spawn(async move {
                        while let Some(message) = outbound_rx.recv().await {
                            if ws_sender.send(message).await.is_err() {
                                println!("❌ Erreur envoi WebSocket");
                                break;
                            }
                        }
                        println!("📤 Task sender WebSocket terminée");
                    });

                    // BOUCLE PRINCIPALE RECEPTION WEBSOCKET
                    while let Some(msg) = ws_receiver.next().await {
                        match msg {
                            Ok(Message::Text(text)) => {
                                println!("📨 Message reçu : {}", text);
                                
                                match serde_json::from_str::<WebSocketMessage>(&text) {
                                    Ok(WebSocketMessage::Request { id, request }) => {
                                        println!("📥 Requête reçue {} : {:?}", id, request);
                                        if request_tx.send((id, request)).is_err() {
                                            println!("❌ Impossible d'envoyer vers request handler");
                                            break;
                                        }
                                    },
                                    Ok(other) => {
                                        println!("⚠️ Message inattendu : {:?}", other);
                                    },
                                    Err(e) => {
                                        println!("❌ Erreur parsing JSON : {}", e);
                                    }
                                }
                            }
                            Ok(Message::Close(_)) => {
                                println!("📌 Connexion WebSocket fermée par le backend");
                                break;
                            }
                            Err(e) => {
                                println!("❌ Erreur WebSocket: {}", e);
                                break;
                            }
                            _ => {}
                        }
                    }

                    // nettoie les tasks
                    task1.abort();
                    task2.abort();
                    task3.abort();
                    println!("🧹 Connexion WebSocket fermée, nettoyage terminé");
                }
                Err(e) => {
                    eprintln!("❌ Échec connexion backend: {}", e);
                    println!("⏳ Attente 5 secondes avant reconnexion...");
                    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                }
            }

            println!("🔄 Tentative de reconnexion dans 5 secondes...");
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        }
    }

    async fn device_handler(
        mut device_rx: mpsc::UnboundedReceiver<UsbDevice>,
        device_manager: Arc<RwLock<OperationManager>>,
        notification_tx: mpsc::UnboundedSender<AgentNotification>,
    ) {
        while let Some(mut device) = device_rx.recv().await {
            println!("💾 Traitement du device: {}", device.device_id);
            println!("   📁 Device path: {:?}", device.device_path);

            println!("🚀 Début montage device {}...", device.device_id);
            let start_time = std::time::Instant::now();
            let device_id = device.device_id.clone();

            match device.mount_device().await {
                Ok(_) => {
                    let duration = start_time.elapsed();
                    println!("✅ Device {} prêt en {:?}", device.device_id, duration);
                    println!("   📁 Mount path: {:?}", device.mount_path);
                    println!("   💾 FS type: {}", device.filesystem_type);
                    
                    // Ajouter au gestionnaire
                    device_manager.write().await.add_device(device);
                    
                    // Vérifier que le device est bien ajouté
                    let device_count = device_manager.read().await.device_count();
                    println!("📊 Nombre de devices actifs: {}", device_count);
                    
                    // Lister tous les devices actifs
                    let active_devices = device_manager.read().await.list_active_devices();
                    println!("📋 Devices actifs: {:?}", active_devices);
                    
                    if let Err(e) = notification_tx.send(AgentNotification::DeviceConnected { 
                        device_id: device_id.clone() 
                    }) {
                        eprintln!("❌ Erreur envoi notification connexion: {}", e);
                    } else {
                        println!("📢 Notification DeviceConnected envoyée pour {}", device_id);
                    }
                }
                Err(e) => {
                    let duration = start_time.elapsed();
                    eprintln!("❌ Échec montage device {} en {:?}: {}", device.device_id, duration, e);
                    
                    if let Err(e) = notification_tx.send(AgentNotification::DeviceDisconnected { 
                        device_id: device.device_id 
                    }) {
                        eprintln!("❌ Erreur envoi notification déconnexion: {}", e);
                    } else {
                        println!("📢 Notification DeviceDisconnected envoyée après échec montage");
                    }
                }
            }
        }
    }

    async fn connect_to_backend_static() -> Result<(
        futures_util::stream::SplitSink<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>, Message>,
        futures_util::stream::SplitStream<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>>
    )> {
        println!("🔐 Configuration connexion TLS...");
        
        let tls_config = build_client_mtls_config(
            "/etc/rustykey/agent.crt",
            "/etc/rustykey/agent.key",
            "/etc/rustykey/ca.crt"
        )?;
        
        let connector = Connector::Rustls(Arc::new(tls_config));
        let url = "wss://rustykey-backend.local:8443/agent/ws";
        
        println!("🌐 Connexion à {}...", url);
        let (ws_stream, _) = connect_async_tls_with_config(
            url,
            None,
            false,
            Some(connector),
        ).await.context("Connexion WebSocket mTLS échouée")?;
        
        println!("✅ Connexion WebSocket établie");
        Ok(ws_stream.split())
    }

    async fn handle_backend_request(
        device_manager: &Arc<RwLock<OperationManager>>,
        request: FileRequest,
    ) -> FileResponse {
        let mut manager = device_manager.write().await;
        
        match request {
            FileRequest::ListFiles { path } => manager.list_files(&path).await,
            FileRequest::ReadFile { path } => manager.read_file(&path).await,
            FileRequest::WriteFile { path, data } => manager.write_file(&path, data).await,
            FileRequest::DeleteFile { path } => manager.delete_file(&path).await,
            FileRequest::CreateDirectory { path } => manager.create_directory(&path).await,
            FileRequest::GetMetadata { path } => manager.get_metadata(&path).await,
        }
    }
}