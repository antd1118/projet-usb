use axum::{extract::ws::WebSocketUpgrade, response::Response, routing::get, Router, Extension};
use tower::make::Shared;
mod expose_s3;
mod websocket;
mod audit;
use expose_s3::RustykeyS3Service;
use shared::{build_server_mtls_config, build_server_tls_config};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("🚀 Démarrage du backend RustyKey...");

    // Préparation
    let s3_service = RustykeyS3Service::new();

    // mTLS pour communication agent<=>backend
    let mtls_config = build_server_mtls_config(
        "backend/backend.crt",
        "backend/backend.key",
        "backend/ca.crt",
    )?;

    // TLS pour communication utilisateur<=>backend
    let tls_server_config = build_server_tls_config(
        "backend/backend.crt",
        "backend/backend.key",
    )?;

    let websocket_router = Router::new()
        .route("/agent/ws", get(websocket_handler))
        .layer(Extension(s3_service.clone()));

    println!("🌐 Backend démarré :");
    println!("📡 Agents WebSocket : https://rustykey-backend.local:8443/agent/ws");
    println!("🗄️ API S3 : https://rustykey-backend.local:8080/*");

    let agents_addr = std::net::SocketAddr::from(([0, 0, 0, 0], 8443));
    
    let agents_handle = tokio::spawn(async move {
        let websocket_service = websocket_router.into_service();
        axum_server::bind_rustls(agents_addr, mtls_config)
            .serve(Shared::new(websocket_service))
            .await
            .map_err(|e| anyhow::anyhow!("Erreur serveur Agents: {}", e))
    });

    let s3_handle = tokio::spawn(async move {

        // Crée le router S3
        let s3_router = s3_service.create_router();
        
        let s3_addr = std::net::SocketAddr::from(([0, 0, 0, 0], 8080));

        axum_server::bind_rustls(s3_addr, tls_server_config)
            .serve(s3_router.into_make_service())
            .await
            .map_err(|e| anyhow::anyhow!("Erreur serveur S3: {}", e))
    });
    
    // Erreurs si l'un des deux serveurs est down
    tokio::select! {
        result = agents_handle => {
            match result {
                Ok(Ok(_)) => println!("✅ Serveur agents terminé proprement"),
                Ok(Err(e)) => println!("❌ Erreur serveur agents: {}", e),
                Err(e) => println!("❌ Erreur task agents: {}", e),
            }
        }
        result = s3_handle => {
            match result {
                Ok(Ok(_)) => println!("✅ Serveur S3 terminé proprement"),
                Ok(Err(e)) => println!("❌ Erreur serveur S3: {}", e),
                Err(e) => println!("❌ Erreur task S3: {}", e),
            }
        }
    }

    Ok(())
}

async fn websocket_handler(ws: WebSocketUpgrade, Extension(s3_service): Extension<RustykeyS3Service>) -> Response {
    // On upgrade la connexion HTTP en WebSocket
    ws.on_upgrade(|socket| websocket::handle_agent_connection(socket, s3_service))
}