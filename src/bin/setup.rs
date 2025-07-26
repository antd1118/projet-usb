use std::fs;
use std::io::{self,Write};
use std::process::{Command, Stdio};
use std::path::{Path, PathBuf};
use std::os::unix::fs::PermissionsExt;
fn main() -> Result<(), Box<dyn std::error::Error>> {

    println!("Configuration de l'agent RustyKey. L'application restera active même aprés redémarage. Reexcutez le setup pour la désinstaller.");

    let user_exists = Command::new("id")
        .arg("usb-agent")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?
        .success();
    let rule_exists = Path::new("/etc/udev/rules.d/99-rustykey.rules").exists();
    let service_exists = Path::new("/etc/systemd/system/rustykey-agent.service").exists();

    if user_exists && rule_exists && service_exists {
        println!("ℹ️ L'application RustyKey est déjà configurée.");
        println!("Voulez-vous la désinstaller ? (y/n)");
        io::stdout().flush()?;
        let mut answer = String::new();
        io::stdin().read_line(&mut answer)?;
        if answer.trim().to_lowercase() == "y" {
            disable_app()?;
            println!("✅ Application RustyKey désinstallée.");
            return Ok(());
        } else {
            println!("❌ Abandon du setup. RustyKey est déjà configurée.");
            return Ok(());
        }
    }

    let udevadm_found = Command::new("which")
    .arg("udevadm")
    .stdout(Stdio::null())
    .stderr(Stdio::null())
    .status()?
    .success();

    if !udevadm_found {
        return Err("⛔ udevadm n'est pas présent sur ce système. RustyKey nécessite udev.".into());
    }

    create_user()?;
    disable_automount()?;
    set_agent_path()?;
    create_service()?;

    println!("🎉 Setup terminé.");
    Ok(())
}

fn create_user() -> Result<(), Box<dyn std::error::Error>> {

    // Vérifier si l'utilisateur existe pas déjà
    let user_exists = Command::new("id")
        .arg("usb-agent")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?
        .success();

    // Imaginons à tout hashard qu'un utilisateur soit déjà existant avec ce nom mais sans la configuration requise
    if user_exists {

        let mut requires_recreate = false;

        let output = Command::new("getent")
            .args(&["passwd", "usb-agent"])
            .output()?;

        let line = String::from_utf8_lossy(&output.stdout);
        let fields: Vec<&str> = line.split(':').collect();
        //on récupère les champs correspondants aux configurations requises
        if fields.len() < 7 {
            println!("🚨 L'entrée de l'utilisateur usb-agent est corrompue ou incomplète ({} champ(s))", fields.len());
            requires_recreate = true;
        } else {
            let shell = fields[6].trim();
            let uid: u32 = fields[2].parse()?;
            if shell != "/usr/sbin/nologin" {
                println!("⚠️ L'utilisateur usb-agent doit avoir un shell bloqué (/usr/sbin/nologin)");
                requires_recreate = true;
            }
            if uid >= 1000 {
                println!("⚠️ L'utilisateur usb-agent doit être un compte système (UID < 1000)");
                requires_recreate = true;
            }
        }

        if requires_recreate {
            println!("⚠️ L'utilisateur usb-agent existe déjà mais n'a pas la configuration requise pour l'application. Voulez vous le supprimer et le recréer ? (y/n)");
            io::stdout().flush()?;
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;

            if input.trim().to_lowercase() == "y" {
                let delete_status = Command::new("userdel")
                    .arg("usb-agent")
                    .status()?;
                if !delete_status.success() {
                    return Err("❌ Échec de suppression de l'utilisateur usb-agent".into());
                }
                println!("✅ Utilisateur usb-agent supprimé. Recréation...");
            } else {
                return Err("❌ Abandon du setup. Veuillez changer le nom de votre utilisateur ou sauvegarder ces données et relancer le setup.".into());
            }
        } else {
            println!("✅ L'utilisateur usb-agent existe déjà avec la configuration requise.");
            return Ok(());
        }
    }


    //A ce stade, l'utilisateur n'existe pas ou vient d'être supprimé, on le crée
    println!("👤 Création de l'utilisateur usb-agent...");

    let create = Command::new("useradd")
        .args(&["-r", "-M", "-s", "/usr/sbin/nologin", "usb-agent"]) // -r: compte système, -M: pas de home, -s: shell bloqué
        .status()?;

    if !create.success() {
        return Err("❌ Échec de création de l'utilisateur usb-agent".into());
    }

    println!("✅ Utilisateur usb-agent créé avec succès.");

    Ok(())
}

fn disable_automount() -> Result<(), Box<dyn std::error::Error>> {
    let rule_path = "/etc/udev/rules.d/99-rustykey.rules";

    let udev_rule = r#"
    # Règle RustyKey : empêche le montage auto des périphériques USB de stockage
    ACTION=="add", SUBSYSTEM=="block", SUBSYSTEMS=="usb", ENV{ID_FS_USAGE}=="filesystem", ENV{UDISKS_IGNORE}="1", ENV{UDISKS_SYSTEM}="0", TAG-="uaccess"
    "#;

    let udev_rule2 = r#"
    # Règle RustyKey : restreint les acces aux périphériques USB de stockage
    ACTION=="add", SUBSYSTEM=="block", SUBSYSTEMS=="usb", RUN+="/usr/bin/chown usb-agent /dev/%k", RUN+="/usr/bin/chmod 600 /dev/%k"
    "#;

    if !Path::new(rule_path).exists() {
        println!("🛡️ Configuration des règles udev...");
        fs::write(rule_path, format!("{}\n\n{}", udev_rule.trim(), udev_rule2.trim()))?;
        
        let reload = Command::new("udevadm")
            .args(&["control", "--reload-rules"])
            .status()?;
        if !reload.success() {
            return Err("❌ Erreur lors du rechargement des règles udev.".into());
        }

        let trigger = Command::new("udevadm")
            .args(&["trigger", "--action=add","--subsystem-match=block", "--property-match=SUBSYSTEMS=usb"])
            .status()?;
        if !trigger.success() {
            return Err("❌ Échec lors du déclenchement des règles udev.".into());
        }

        println!("✅ Règle udev installée et rechargée avec succès.");
    } else {
        println!("✅ La règle udev est déjà en place.");
    }

    Ok(())
}

fn create_service() -> Result<(), Box<dyn std::error::Error>> {
    let service_path = "/etc/systemd/system/rustykey-agent.service";

    if !Path::new(service_path).exists() {
        println!("⚙️ Création du service systemd rustykey-agent...");

        let service_content = r#"[Unit]
        Description=RustyKey USB Agent
        After=network-online.target
        Wants=network-online.target

        [Service]
        User=usb-agent
        ExecStart=/usr/local/bin/rustykey-agent
        
        # Isolation et sécurité maximale
        NoNewPrivileges=true
        PrivateTmp=true
        ProtectSystem=strict
        ProtectHome=true
        ReadOnlyPaths=/
        ProtectKernelModules=true
        ProtectKernelTunables=true
        ProtectControlGroups=true
        ProtectProc=invisible
        MemoryDenyWriteExecute=true
        RestrictSUIDSGID=true
        RestrictRealtime=true
        LockPersonality=true
        SystemCallFilter=~@reboot
        SystemCallArchitectures=native

        # Capability pour autoriser le montage/démontage
        CapabilityBoundingSet=CAP_SYS_ADMIN
        AmbientCapabilities=CAP_SYS_ADMIN

        # Redémarrage automatique en cas de problème
        Restart=on-failure
        RestartSec=5s

        [Install]
        WantedBy=multi-user.target
        "#;

        fs::write(service_path, service_content)?;

        let reload = Command::new("systemctl").args(&["daemon-reload"]).status()?;
        if !reload.success() {
            return Err("❌ Échec du rechargement du démon systemd.".into());
        }

        let enable = Command::new("systemctl").args(&["enable", "rustykey-agent.service"]).status()?;
        if !enable.success() {
            return Err("❌ Échec de l'activation du service.".into());
        }

        let start = Command::new("systemctl").args(&["start", "rustykey-agent.service"]).status()?;
        if !start.success() {
            return Err("❌ Échec du démarrage du service.".into());
        }

        println!("✅ Service rustykey-agent installé, activé et démarré !");
    } else {
        println!("✅ Le service systemd rustykey-agent existe déjà.");
    }

    Ok(())
}

fn disable_app() -> Result<(), Box<dyn std::error::Error>> {

    // supprimer service systemd
    let _ = Command::new("systemctl").args(&["stop", "rustykey-agent.service"]).status();
    let _ = Command::new("systemctl").args(&["disable", "rustykey-agent.service"]).status();
    fs::remove_file("/etc/systemd/system/rustykey-agent.service")?;
    let _ = Command::new("systemctl").arg("daemon-reload").status();

    // supprimer règle udev
    fs::remove_file("/etc/udev/rules.d/99-rustykey.rules")?;
    let _ = Command::new("udevadm").args(&["control", "--reload-rules"]).status();
    let _ = Command::new("udevadm").args(&["trigger", "--action=remove","--subsystem-match=block", "--property-match=SUBSYSTEMS=usb"]).status();

    // supprimer utilisateur usb-agent
    let _ = Command::new("userdel").arg("usb-agent").status();

    Ok(())
}

// Fonction pour trouver le chemin de l'executable agent et créer un lien symbolique dans /usr/local/bin pour faciliter l'exécution avec systemd

fn set_agent_path() -> Result<(), Box<dyn std::error::Error>> {
    let prog_path = "/usr/local/bin/rustykey-agent";

    // auto-détection dans le même dossier que le setup
    let setup_dir = std::env::current_exe()?.parent().unwrap().to_path_buf();
    let candidate = setup_dir.join("rustykey-agent");
    let agent_path = if candidate.exists() {
        candidate
    } else {
        // sinon demander à l'utilisateur
        println!("Veuillez entrer le chemin complet vers le binaire 'rustykey-agent' :");
        io::stdout().flush()?;
        let mut answer = String::new();
        io::stdin().read_line(&mut answer)?;
        let answer = answer.trim();
        let candidate = PathBuf::from(answer);
        if !candidate.exists() {
            return Err(format!("❌ Chemin invalide ou binaire inexistant : {answer}").into());
        }
        candidate
    };

    // création du lien symbolique
    if Path::new(prog_path).exists() {
        fs::remove_file(prog_path)?;
    }
    fs::copy(&agent_path, prog_path)?;
    fs::set_permissions(prog_path, fs::Permissions::from_mode(0o755))?;
    println!("✅ Programme copié dans {:?}", prog_path);
    Ok(())
}
