use anyhow::Result;
use caps::{CapSet, clear};

mod udev_monitor;
mod device_manager;
mod websocket;

use websocket::RustykeyAgent;

#[tokio::main]
async fn main() -> Result<()> {
    println!("🚀 Démarrage de l'agent RustyKey...");

    // On dropp les capabilities pour le processus principal
    drop_cap()?;

    // Démarre l'agent
    let mut agent = RustykeyAgent::new().await?;
    agent.run().await?;

    Ok(())
}

fn drop_cap() -> Result<()> {
    // On supprime les capabilités mais on garde Ambient pour transmission au worker
    for set in [CapSet::Effective, CapSet::Permitted, CapSet::Inheritable] {
        if let Err(e) = clear(None, set) {
            eprintln!("Erreur clear cap {:?} : {}", set, e);
        }
    }
    Ok(())
}