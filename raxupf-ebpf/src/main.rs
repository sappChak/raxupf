#![no_std]
#![no_main]

use core::net::Ipv4Addr;

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::{debug, error, warn};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
};
use raxupf_ebpf::{
    GTPU_DST_PORT,
    gtpu::GtpuMessageType,
    gtpu_helpers::{encapsulate_into_gtpu, route_packet_l2},
    helpers::{parse_l3_l4_headers, ptr_at_mut},
    maps::{DOWNLINK_PDRS, INT_IPS},
    message_handlers::{
        handle_echo_request, handle_echo_response, handle_end_marker, handle_error_indication,
        handle_gpdu_message,
    },
    parser::PacketContext,
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
        error!(ctx, "no inner headers inside, dropping");
        return Ok(xdp_action::XDP_DROP);
    };

    debug!(ctx, "incoming gtp-u");

    match &inner.gtpu.message_type {
        GtpuMessageType::GPdu => return handle_gpdu_message(ctx, packet_ctx),
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

fn handle_n6_packet(ctx: &XdpContext, packet_ctx: &PacketContext) -> Result<u32, ()> {
    if let Some(dl_pdrs) = unsafe { DOWNLINK_PDRS.get(packet_ctx.dst_ipv4().to_bits()) } {
        let ParsedPdr {
            teid,
            qfi,
            dscp,
            remote_ipv4,
            action,
        } = match process_pdrs(ctx, packet_ctx, dl_pdrs) {
            Ok(ok) => ok,
            Err(err) => return Ok(err),
        };

        let local_ipv4 = packet_ctx.upf_ipv4();

        let (niph_len, protocol) = match action {
            PdrAction::Create => {
                match encapsulate_into_gtpu(ctx, local_ipv4, remote_ipv4, dscp, qfi, teid) {
                    Ok(ip_len) => (ip_len, IpProto::Udp),
                    Err(_) => {
                        error!(ctx, "failed to encapsulate packet into gtp-u");
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
            remote_ipv4,
            protocol,
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
        debug!(ctx, "no upf ipv4 configured, dropping");
        return Ok(xdp_action::XDP_DROP);
    };

    let iph: &Ipv4Hdr = unsafe { &*ptr_at_mut(&ctx, EthHdr::LEN)? };
    let (parsed_iph, parsed_ports) = parse_l3_l4_headers(&ctx, iph, EthHdr::LEN)?;
    let mut packet_ctx = PacketContext::new(parsed_iph, upf_ipv4, parsed_ports);

    if let Some(ports) = packet_ctx.ports()
        && packet_ctx.dst_ipv4() == upf_ipv4
        && ports.dst_port() == GTPU_DST_PORT
    {
        if let Err(e) = packet_ctx.parse_inner(&ctx) {
            debug!(ctx, "failed to parse inner headers, dropping");
            return Ok(e);
        };
        return handle_gtp_packet(&ctx, &packet_ctx);
    }

    handle_n6_packet(&ctx, &packet_ctx)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
