#![no_std]
#![no_main]

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::{debug, error, warn};
use network_types::{eth::EtherType, ip::IpProto};
use raxupf_common::{PROG_GTP, PROG_N6};
use raxupf_ebpf::{
    GTPU_DST_PORT,
    gtpu::{GtpuMessageType, encapsulate_into_gtpu},
    helpers::{parse_eth_hdr, parse_ip_header, parse_l4_header, route_packet_l2},
    maps::{DOWNLINK_PDRS_V4, DOWNLINK_PDRS_V6, INT_IPS_V4, INT_IPS_V6, JUMP_TABLE, PKT_CTX},
    message_handlers::{
        handle_echo_request, handle_echo_response, handle_end_marker, handle_error_indication,
        handle_gpdu_message,
    },
    parser::{PacketContext, PdrAction, parse_gtp},
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
    let (ether_type, offset) = match parse_eth_hdr(ctx, 0) {
        Ok((ether_type, offset)) => (ether_type, offset),
        Err(_) => return Ok(xdp_action::XDP_PASS),
    };

    let (n3_ip, n9_ip) = match ether_type {
        EtherType::Ipv4 => {
            let (n3, n9) =
                if let (Some(n3_ipv4), Some(n9_ipv4)) = (INT_IPS_V4.get(0), INT_IPS_V4.get(1)) {
                    (Ipv4Addr::from_bits(*n3_ipv4), Ipv4Addr::from_bits(*n9_ipv4))
                } else {
                    debug!(ctx, "no UPF IPv4 configured, dropping");
                    return Ok(xdp_action::XDP_DROP);
                };
            (IpAddr::V4(n3), IpAddr::V4(n9))
        }
        EtherType::Ipv6 => {
            let (n3, n9) =
                if let (Some(n3_ipv6), Some(n9_ipv6)) = (INT_IPS_V6.get(0), INT_IPS_V6.get(1)) {
                    (Ipv6Addr::from_bits(*n3_ipv6), Ipv6Addr::from_bits(*n9_ipv6))
                } else {
                    debug!(ctx, "no UPF IPv6 configured, dropping");
                    return Ok(xdp_action::XDP_DROP);
                };
            (IpAddr::V6(n3), IpAddr::V6(n9))
        }
        _ => return Ok(xdp_action::XDP_PASS),
    };

    let (parsed_ip, offset) = parse_ip_header(ctx, offset)?;
    let (parsed_ports, offset) = unsafe { parse_l4_header(ctx, parsed_ip.proto(), offset)? };
    let packet_context = PacketContext::new(parsed_ip, parsed_ports, n3_ip);

    let slot = PKT_CTX.get_ptr_mut(0).ok_or(())?;
    unsafe { slot.write(packet_context) };
    let pkt_ctx = unsafe { &mut *slot };

    if let Some(ports) = pkt_ctx.ports()
        && *pkt_ctx.dst_ip() == n3_ip
        && ports.dst_port() == GTPU_DST_PORT
    {
        let parsed_gtp = match parse_gtp(ctx, n3_ip, offset) {
            Ok((gtp, _)) => gtp,
            Err(_) => {
                debug!(ctx, "failed to parse inner headers, dropping");
                return Ok(xdp_action::XDP_DROP);
            }
        };
        pkt_ctx.set_gtp(parsed_gtp);
        return jump(ctx, PROG_GTP);
    }

    jump(ctx, PROG_N6)
}

fn handle_gtp_pkt(ctx: &XdpContext, pkt_ctx: &PacketContext) -> Result<u32, ()> {
    let inner = if let Some(inner) = pkt_ctx.gtp() {
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
    let dl_pdrs = match pkt_ctx.dst_ip() {
        IpAddr::V4(ipv4_addr) => unsafe { DOWNLINK_PDRS_V4.get(ipv4_addr.to_bits()) },
        IpAddr::V6(ipv6_addr) => unsafe { DOWNLINK_PDRS_V6.get(ipv6_addr.to_bits()) },
    };
    if let Some(dl_pdrs) = dl_pdrs {
        let parsed_pdr = match process_pdrs(ctx, pkt_ctx, dl_pdrs) {
            Ok(ok) => ok,
            Err(err) => return Ok(err),
        };

        let local_ip = pkt_ctx.upf_ip();

        let (niph_len, protocol) = match parsed_pdr.action() {
            PdrAction::Create => {
                match encapsulate_into_gtpu(
                    ctx,
                    local_ip,
                    parsed_pdr.remote_ip(),
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
            local_ip,
            parsed_pdr.remote_ip(),
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
