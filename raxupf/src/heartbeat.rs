use log::debug;

pub async fn handle_hearbeat_request() -> anyhow::Result<()> {
    debug!("incoming heartbeat request");
    Ok(())
}
