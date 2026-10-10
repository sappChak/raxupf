use std::net::SocketAddr;

use rs_pfcp::message::{
    Message, heartbeat_request::HeartbeatRequest, heartbeat_response::HeartbeatResponseBuilder,
};

use crate::pfcp::PfcpContext;

pub async fn handle_hearbeat_request(
    ctx: &PfcpContext,
    req: &HeartbeatRequest,
    cp_addr: SocketAddr,
) -> anyhow::Result<()> {
    let response =
        HeartbeatResponseBuilder::new(req.sequence()).recovery_time_stamp(ctx.recovery_ts());
    ctx.send_response(&response.marshal(), cp_addr).await
}
