#![no_std]
#![no_main]

use core::net::Ipv4Addr;

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::{debug, error, warn};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
};
use raxupf_common::{PROG_GTP, PROG_N6};
use raxupf_ebpf::{
    GTPU_DST_PORT,
    gtpu::{GtpuMessageType, encapsulate_into_gtpu},
    helpers::{parse_l3_l4_headers, ptr_at_mut, route_packet_l2},
    maps::{DOWNLINK_PDRS, INT_IPS, JUMP_TABLE, PKT_CTX},
    message_handlers::{
        handle_echo_request, handle_echo_response, handle_end_marker, handle_error_indication,
        handle_gpdu_message,
    },
    parser::{PacketContext, PdrAction},
    pdr::process_pdrs,
};

/// Entry program: parse pkt, then jump to a target
#[xdp]
pub fn raxupf(ctx: XdpContext) -> u32 {
    match try_raxupf(&ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

/// Target: GTP-U (N3/N9) packets
#[xdp]
pub fn raxupf_gtp(ctx: XdpContext) -> u32 {
    let Some(ptr) = PKT_CTX.get_ptr(0) else {
        return xdp_action::XDP_ABORTED;
    };
    let packet_ctx = unsafe { &*ptr };
    match handle_gtp_pkt(&ctx, packet_ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

/// Target: plain IP (N6) packets
#[xdp]
pub fn raxupf_n6(ctx: XdpContext) -> u32 {
    let Some(ptr) = PKT_CTX.get_ptr(0) else {
        return xdp_action::XDP_ABORTED;
    };
    let pkt_ctx = unsafe { &*ptr };
    match handle_n6_pkt(&ctx, pkt_ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
fn jump(ctx: &XdpContext, idx: u32) -> Result<u32, ()> {
    unsafe { JUMP_TABLE.tail_call(ctx, idx) };
    error!(ctx, "tail call failed, dropping");
    Ok(xdp_action::XDP_DROP)
}

#[inline(always)]
fn try_raxupf(ctx: &XdpContext) -> Result<u32, ()> {
    let ethh = ptr_at_mut::<EthHdr>(ctx, 0)?;
    match unsafe { (*ethh).ether_type() } {
        Ok(EtherType::Ipv4) => {}
        Ok(EtherType::Arp) => {
            debug!(ctx, "incoming arp request, passing");
            return Ok(xdp_action::XDP_PASS);
        }
        // TODO: Add IPv6 support
        _ => return Ok(xdp_action::XDP_PASS),
    }

    // TODO: different IPs for N3 and N9?
    let upf_ipv4 = if let Some(ipv4) = INT_IPS.get(0) {
        Ipv4Addr::from_bits(*ipv4)
    } else {
        debug!(ctx, "no UPF IPv4 configured, dropping");
        return Ok(xdp_action::XDP_DROP);
    };

    let iph = ptr_at_mut::<Ipv4Hdr>(ctx, EthHdr::LEN)?;
    let (parsed_iph, parsed_ports) = unsafe { parse_l3_l4_headers(ctx, iph, EthHdr::LEN)? };

    let slot = PKT_CTX.get_ptr_mut(0).ok_or(())?;
    unsafe { slot.write(PacketContext::new(parsed_iph, upf_ipv4, parsed_ports)) };
    let pkt_ctx = unsafe { &mut *slot };

    if let Some(ports) = pkt_ctx.ports()
        && pkt_ctx.dst_ipv4() == upf_ipv4
        && ports.dst_port() == GTPU_DST_PORT
    {
        if let Err(e) = pkt_ctx.parse_inner(ctx) {
            debug!(ctx, "failed to parse inner headers, dropping");
            return Ok(e);
        };
        return jump(ctx, PROG_GTP);
    }

    jump(ctx, PROG_N6)
}

fn handle_gtp_pkt(ctx: &XdpContext, pkt_ctx: &PacketContext) -> Result<u32, ()> {
    let inner = if let Some(inner) = pkt_ctx.inner() {
        inner
    } else {
        error!(ctx, "no inner headers inside, dropping");
        return Ok(xdp_action::XDP_DROP);
    };

    match &inner.gtpu.message_type {
        GtpuMessageType::GPdu => return handle_gpdu_message(ctx, pkt_ctx),
        GtpuMessageType::EchoRequest => return handle_echo_request(ctx),
        GtpuMessageType::EchoResponse => return handle_echo_response(ctx),
        GtpuMessageType::ErrorIndication => return handle_error_indication(ctx),
        GtpuMessageType::EndMarker => return handle_end_marker(ctx),
        _ => {
            warn!(ctx, "unsupported gtp-u message type");
        }
    }

    Ok(xdp_action::XDP_DROP)
}

fn handle_n6_pkt(ctx: &XdpContext, pkt_ctx: &PacketContext) -> Result<u32, ()> {
    if let Some(dl_pdrs) = unsafe { DOWNLINK_PDRS.get(pkt_ctx.dst_ipv4().to_bits()) } {
        let parsed_pdr = match process_pdrs(ctx, pkt_ctx, dl_pdrs) {
            Ok(ok) => ok,
            Err(err) => return Ok(err),
        };

        let local_ipv4 = pkt_ctx.upf_ipv4();

        let (niph_len, protocol) = match parsed_pdr.action() {
            PdrAction::Create => {
                match encapsulate_into_gtpu(
                    ctx,
                    local_ipv4,
                    parsed_pdr.remote_ipv4(),
                    parsed_pdr.dscp(),
                    parsed_pdr.qfi(),
                    parsed_pdr.teid(),
                ) {
                    Ok(ip_len) => (ip_len, IpProto::Udp),
                    Err(_) => {
                        error!(ctx, "failed to encapsulate packet into gtp-u, dropping");
                        return Ok(xdp_action::XDP_DROP);
                    }
                }
            }
            _ => {
                debug!(ctx, "unsupported PDR action for downlink packet, dropping");
                return Ok(xdp_action::XDP_DROP);
            }
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

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
