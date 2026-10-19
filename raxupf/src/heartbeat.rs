use rs_pfcp::message::{
    HeartbeatResponse, Message, heartbeat_request::HeartbeatRequest,
    heartbeat_response::HeartbeatResponseBuilder,
};

use crate::pfcp::PfcpContext;

pub async fn handle_hearbeat_request(
    ctx: &PfcpContext,
    req: &HeartbeatRequest,
) -> anyhow::Result<HeartbeatResponse> {
    let response = HeartbeatResponseBuilder::new(req.sequence())
        .recovery_time_stamp(ctx.recovery_ts())
        .build();
    Ok(response)
}
