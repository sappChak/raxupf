use aya_ebpf::{bindings::xdp_action, programs::XdpContext};
use aya_log_ebpf::{debug, error};
use network_types::ip::IpProto;

use crate::{
    gtpu_helpers::{decapsulate_gtpu, route_packet_l2, update_gtpu},
    maps::UPLINK_PDRS,
    parser::PacketContext,
    pdr::{ParsedPdr, PdrAction, process_pdrs},
};

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

pub fn handle_gpdu_message(ctx: &XdpContext, pkt_ctx: &PacketContext) -> Result<u32, ()> {
    let inner = if let Some(inner) = pkt_ctx.inner() {
        inner
    } else {
        return Ok(xdp_action::XDP_ABORTED);
    };

    let ext_tot_len = inner.psc.ext_tot_len();
    let upf_ip = pkt_ctx.upf_ipv4();

    if let Some(ul_pdrs) = unsafe { UPLINK_PDRS.get(inner.gtpu.local_fteid.teid()) } {
        let ParsedPdr {
            teid,
            qfi,
            dscp,
            remote_ipv4,
            action,
        } = match process_pdrs(ctx, pkt_ctx, ul_pdrs) {
            Ok(ok) => ok,
            Err(err) => return Ok(err),
        };

        let niph_len: u16 = match action {
            PdrAction::Remove => match decapsulate_gtpu(ctx, ext_tot_len) {
                Ok(len) => len,
                Err(_) => {
                    error!(ctx, "failed to decapsulate gtp-u packet");
                    return Ok(xdp_action::XDP_DROP);
                }
            },
            PdrAction::Forward => update_gtpu(ctx, upf_ip, remote_ipv4)?,
            _ => return Ok(xdp_action::XDP_DROP),
        };

        debug!(ctx, "ip tot len is: {}", niph_len);

        return route_packet_l2(
            ctx,
            upf_ip,
            remote_ipv4,
            IpProto::Udp, // it should be provided by the PacketContext
            niph_len,
            ctx.ingress_ifindex() as u32,
        );
    }

    Ok(xdp_action::XDP_PASS)
}
