
use std::fs::OpenOptions;
use std::io::Write;
use chrono::Utc;

// Pour l'instant on logg toutes les opérations dans /var/log/rustykey_audit.log
// (besoin d'executer le backend en sudo)
//todo
pub fn log_event(session_id: &str, user: &str, action: &str, path: &str, bytes: usize, hash: &str) {
    let timestamp = Utc::now().to_rfc3339();
    let log_line = format!(
        "{timestamp} | session={session_id} | user={user} | action={action} | path={path} | bytes={bytes} | hash={hash}\n"
    );

    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open("/var/log/rustykey_audit.log")
    {
        let _ = file.write_all(log_line.as_bytes());
    } else {
        eprintln!("Erreur écriture des logs: {log_line}");
    }
}
