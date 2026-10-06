use aya_ebpf::{bindings::xdp_action, programs::XdpContext};
use aya_log_ebpf::{debug, error};
use network_types::ip::IpProto;

use crate::{
    gtpu::{decapsulate_gtpu, update_gtpu},
    helpers::route_packet_l2,
    maps::UPLINK_PDRS,
    parser::{PacketContext, PdrAction},
    pdr::process_pdrs,
};

pub fn handle_gpdu_message(ctx: &XdpContext, pkt_ctx: &PacketContext) -> Result<u32, ()> {
    let inner = if let Some(inner) = pkt_ctx.inner() {
        inner
    } else {
        return Ok(xdp_action::XDP_DROP);
    };

    let ext_tot_len = inner.psc.ext_tot_len();
    let local_ipv4 = pkt_ctx.upf_ipv4();

    if let Some(ul_pdrs) = unsafe { UPLINK_PDRS.get(inner.gtpu.local_fteid.teid()) } {
        let parsed_pdr = match process_pdrs(ctx, pkt_ctx, ul_pdrs) {
            Ok(pdr) => pdr,
            Err(err) => return Ok(err),
        };

        let (niph_len, protocol) = match parsed_pdr.action() {
            PdrAction::Remove => match decapsulate_gtpu(ctx, ext_tot_len) {
                Ok(len) => (len, inner.ipv4().protocol()),
                Err(_) => {
                    error!(ctx, "failed to decapsulate gtp-u packet");
                    return Ok(xdp_action::XDP_DROP);
                }
            },
            PdrAction::Forward => (
                update_gtpu(ctx, local_ipv4, parsed_pdr.remote_ipv4())?,
                IpProto::Udp,
            ),
            _ => return Ok(xdp_action::XDP_DROP),
        };

        return route_packet_l2(
            ctx,
            local_ipv4,
            parsed_pdr.remote_ipv4(),
            protocol,
            niph_len,
            ctx.ingress_ifindex() as u32,
        );
    }

    Ok(xdp_action::XDP_PASS)
}

pub fn handle_echo_request(ctx: &XdpContext) -> Result<u32, ()> {
    debug!(ctx, "incoming echo request");
    Ok(xdp_action::XDP_PASS)
}

pub fn handle_echo_response(ctx: &XdpContext) -> Result<u32, ()> {
    // TODO: Implement Echo Response GTP-U message
    debug!(ctx, "incoming echo response");
    Ok(xdp_action::XDP_PASS)
}

pub fn handle_error_indication(ctx: &XdpContext) -> Result<u32, ()> {
    // TODO: may contain UDP port extension header (see 5.2.2.1)
    debug!(ctx, "incoming error indication");
    Ok(xdp_action::XDP_PASS)
}

pub fn handle_end_marker(ctx: &XdpContext) -> Result<u32, ()> {
    // TODO: Handle G-PDU (see 5.2.2.7)
    debug!(ctx, "incoming end marker");
    Ok(xdp_action::XDP_PASS)
}
