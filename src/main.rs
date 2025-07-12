use udev::{MonitorBuilder, EventType};

fn main() -> anyhow::Result<()> {
    let mut monitor = MonitorBuilder::new()?
        .match_subsystem("block")?
        .listen()?;

    println!("📡 Surveillance USB démarrée...");

    for event in monitor {
        let dev = event.device();
        let action = event.event_type();
        let is_usb = dev.property_value("ID_BUS")
            .map(|v| v.to_str() == Some("usb"))
            .unwrap_or(false);

        if is_usb && (action == EventType::Add || action == EventType::Remove) {
            println!("🔌 Action: {:?}, devnode: {:?}", action, dev.devnode());
        }
    }
    Ok(())
}
