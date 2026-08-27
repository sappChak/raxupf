#![no_std]
#![no_main]

use core::net::Ipv4Addr;

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::{error, warn};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};
use raxupf_ebpf::{
    GTPU_DST_PORT,
    gtpu::GtpuMessageType,
    gtpu_helpers::{encapsulate_into_gtpu, route_packet_l2},
    helpers::{ptr_at, ptr_at_mut},
    maps::{INT_IPS, IP_TO_SESSION, SESSION_CONTEXT},
    message_handlers::{
        handle_echo_request, handle_echo_response, handle_end_marker, handle_error_indication,
        handle_gpdu_message,
    },
    parser::{PacketContext, ParsedIpv4},
    pdr::{ParsedPdr, PdrAction, process_pdrs},
};

#[xdp]
pub fn raxupf(ctx: XdpContext) -> u32 {
    match handle_ul_dl(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn handle_gtp_packet(ctx: &XdpContext, packet_ctx: &PacketContext) -> Result<u32, ()> {
    let inner = if let Some(inner) = packet_ctx.inner() {
        inner
    } else {
        return Ok(xdp_action::XDP_ABORTED);
    };

    let message_type = &inner.gtpu.message_type;

    match message_type {
        GtpuMessageType::GPdu => return handle_gpdu_message(ctx, packet_ctx),
        GtpuMessageType::EchoRequest => return handle_echo_request(ctx),
        GtpuMessageType::EchoResponse => return handle_echo_response(ctx),
        GtpuMessageType::ErrorIndication => return handle_error_indication(ctx),
        GtpuMessageType::EndMarker => return handle_end_marker(ctx),
        _ => {
            warn!(ctx, "unsupported message type");
        }
    }

    Ok(xdp_action::XDP_DROP)
}

fn handle_packet(ctx: &XdpContext, packet_ctx: &PacketContext) -> Result<u32, ()> {
    let ue_ipv4 = packet_ctx.dst_ipv4();
    let upf_ipv4 = packet_ctx.upf_ipv4();

    if let Some(session_id) = unsafe { IP_TO_SESSION.get(ue_ipv4.to_bits()) }
        && let Some(session_ctx) = unsafe { SESSION_CONTEXT.get(session_id) }
    {
        let ParsedPdr {
            teid,
            qfi,
            tos,
            remote_ipv4,
            action,
        } = match process_pdrs(ctx, packet_ctx, session_ctx.downlink_pdrs()) {
            Ok(ok) => ok,
            Err(err) => return Ok(err),
        };

        let niph_len = match action {
            PdrAction::Create => {
                match encapsulate_into_gtpu(ctx, upf_ipv4, remote_ipv4, tos, qfi, teid) {
                    Ok(ip_len) => ip_len,
                    Err(_) => {
                        error!(ctx, "failed to encapsulate packet into gtp-u");
                        return Ok(xdp_action::XDP_DROP);
                    }
                }
            }
            _ => return Ok(xdp_action::XDP_DROP),
        };

        return route_packet_l2(
            ctx,
            upf_ipv4,
            remote_ipv4,
            IpProto::Udp,
            niph_len,
            ctx.ingress_ifindex() as u32,
        );
    }

    Ok(xdp_action::XDP_PASS)
}

fn handle_ul_dl(ctx: XdpContext) -> Result<u32, ()> {
    let ethh: &EthHdr = unsafe { &*ptr_at_mut(&ctx, 0)? };
    match ethh.ether_type() {
        Ok(EtherType::Ipv4) => {}
        // TODO: Add IPv6 support
        _ => return Ok(xdp_action::XDP_PASS),
    }

    // TODO: different IPs for N3 and N9?
    let upf_ipv4 = if let Some(ipv4) = INT_IPS.get(0) {
        Ipv4Addr::from_bits(*ipv4)
    } else {
        return Ok(xdp_action::XDP_DROP);
    };

    let iph: &Ipv4Hdr = unsafe { &*ptr_at_mut(&ctx, EthHdr::LEN)? };
    let outer_ipv4 = ParsedIpv4::new(iph.src_addr(), iph.dst_addr(), iph.tot_len() as usize);
    let mut packet_ctx = PacketContext::new(outer_ipv4, upf_ipv4);

    match iph.proto() {
        Ok(IpProto::Udp) => {
            let udph: &UdpHdr = unsafe { &*ptr_at_mut(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)? };
            packet_ctx.set_ports(udph.src_port(), udph.dst_port());

            if packet_ctx.dst_ipv4() == upf_ipv4 && packet_ctx.dst_port() == GTPU_DST_PORT {
                if let Err(e) = packet_ctx.parse_inner(&ctx) {
                    return Ok(e);
                };
                return handle_gtp_packet(&ctx, &packet_ctx);
            }
        }
        Ok(IpProto::Tcp) => {
            let tcph: &TcpHdr = unsafe { &*ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)? };
            packet_ctx.set_ports(
                u16::from_be_bytes(tcph.source),
                u16::from_be_bytes(tcph.dest),
            );
        }
        _ => return Ok(xdp_action::XDP_PASS),
    }

    handle_packet(&ctx, &packet_ctx)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
