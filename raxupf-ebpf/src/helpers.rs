use core::{mem, net::IpAddr};

use aya_ebpf::{
    bindings::{bpf_fib_lookup, xdp_action},
    helpers::{bpf_fib_lookup, generated::bpf_csum_diff},
    programs::XdpContext,
};
use aya_log_ebpf::debug;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpHdr, IpProto, Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};
use raxupf_common::fib::FibMacs;

use crate::{
    AF_INET, AF_INET6,
    parser::{ParsedIp, ParsedPorts},
};

#[inline(always)]
pub fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[inline(always)]
pub fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *mut T)
}

#[inline(always)]
pub unsafe fn ipv4_csum(iph: *mut u32, len: u32) -> u16 {
    let csum = unsafe { bpf_csum_diff(core::ptr::null_mut::<u32>(), 0, iph, len, 0) } as u64;
    csum_fold_u64(csum)
}

#[inline(always)]
fn csum_add(csum: u32, addend: u32) -> u32 {
    let res = csum.wrapping_add(addend);
    res.wrapping_add((res < addend) as u32)
}

#[inline(always)]
fn csum_fold_u32(mut csum: u32) -> u16 {
    csum = (csum & 0xffff).wrapping_add(csum >> 16);
    csum = (csum & 0xffff).wrapping_add(csum >> 16);
    !(csum as u16)
}

#[inline(always)]
fn csum_fold_u64(mut csum: u64) -> u16 {
    for _ in 0..4 {
        csum = (csum & 0xffff).wrapping_add(csum >> 16);
    }
    !(csum as u16)
}

#[inline(always)]
pub fn csum_replace4(csum: u32, from: u32, to: u32) -> u16 {
    let tmp = csum_add(!csum, !from);
    csum_fold_u32(csum_add(tmp, to))
}

#[inline(always)]
pub fn u128_to_u324(x: u128) -> [u32; 4] {
    [
        (x >> 96) as u32,
        (x >> 64) as u32,
        (x >> 32) as u32,
        x as u32,
    ]
}

#[inline(always)]
pub fn determine_ip_version(ctx: &XdpContext, offset: usize) -> Result<IpHdr, ()> {
    let version = unsafe { *ptr_at::<u8>(ctx, offset)? } >> 4;
    match version {
        4 => {
            let ipv4_hdr = unsafe { *ptr_at::<Ipv4Hdr>(ctx, offset)? };
            Ok(IpHdr::V4(ipv4_hdr))
        }
        6 => {
            let ipv6_hdr = unsafe { *ptr_at::<Ipv6Hdr>(ctx, offset)? };
            Ok(IpHdr::V6(ipv6_hdr))
        }
        _ => Err(()),
    }
}

#[inline(always)]
pub fn parse_eth_hdr(ctx: &XdpContext, offset: usize) -> Result<(EtherType, usize), ()> {
    let ethh = ptr_at::<EthHdr>(ctx, offset)?;
    let ether_type = unsafe { (*ethh).ether_type() }.map_err(|_| ())?;
    match ether_type {
        EtherType::Ipv4 | EtherType::Ipv6 => Ok((ether_type, offset + EthHdr::LEN)),
        _ => Err(()),
    }
}

#[inline(always)]
pub fn parse_ip_header(ctx: &XdpContext, offset: usize) -> Result<(ParsedIp, usize), ()> {
    let iph = determine_ip_version(ctx, offset)?;
    let (src_ip, dst_ip, proto, tot_len, offset) = match iph {
        IpHdr::V4(ipv4_hdr) => (
            IpAddr::V4(ipv4_hdr.src_addr()),
            IpAddr::V4(ipv4_hdr.dst_addr()),
            ipv4_hdr.proto().map_err(|_| ())?,
            ipv4_hdr.tot_len() as usize,
            offset + Ipv4Hdr::LEN,
        ),
        IpHdr::V6(ipv6_hdr) => (
            IpAddr::V6(ipv6_hdr.src_addr()),
            IpAddr::V6(ipv6_hdr.dst_addr()),
            ipv6_hdr.next_hdr().map_err(|_| ())?,
            ipv6_hdr.payload_len() as usize + Ipv6Hdr::LEN,
            offset + Ipv6Hdr::LEN,
        ),
    };
    Ok((ParsedIp::new(src_ip, dst_ip, proto, tot_len), offset))
}

#[inline(always)]
pub unsafe fn parse_l4_header(
    ctx: &XdpContext,
    proto: IpProto,
    offset: usize,
) -> Result<(Option<ParsedPorts>, usize), ()> {
    match proto {
        IpProto::Udp => {
            let udph = ptr_at::<UdpHdr>(ctx, offset)?;
            let ports = unsafe { ParsedPorts::new((*udph).src_port(), (*udph).dst_port()) };
            Ok((Some(ports), offset + UdpHdr::LEN))
        }
        IpProto::Tcp => {
            let tcph = ptr_at::<TcpHdr>(ctx, offset)?;
            let ports = unsafe {
                ParsedPorts::new(
                    u16::from_be_bytes((*tcph).source),
                    u16::from_be_bytes((*tcph).dest),
                )
            };
            Ok((Some(ports), offset + TcpHdr::LEN))
        }
        _ => Err(()),
    }
}

#[inline(always)]
pub fn do_fib_lookup(
    ctx: &XdpContext,
    fib: &mut bpf_fib_lookup,
    proto: u8,
    saddr: u32,
    daddr: u32,
    tot_len: u16,
    ifindex: u32,
) -> i64 {
    fib.family = AF_INET;
    fib.l4_protocol = proto;
    fib.__bindgen_anon_3.ipv4_src = saddr;
    fib.__bindgen_anon_4.ipv4_dst = daddr;
    fib.__bindgen_anon_1.tot_len = tot_len;
    fib.ifindex = ifindex;

    unsafe {
        bpf_fib_lookup(
            ctx.ctx as *mut _,
            fib,
            core::mem::size_of_val(fib) as i32,
            0, // perform standard lookup (ip route get)
        )
    }
}

#[inline(always)]
pub fn do_fib_lookup6(
    ctx: &XdpContext,
    fib: &mut bpf_fib_lookup,
    proto: u8,
    saddr: [u32; 4],
    daddr: [u32; 4],
    tot_len: u16,
    ifindex: u32,
) -> i64 {
    fib.family = AF_INET6;
    fib.l4_protocol = proto;
    fib.__bindgen_anon_3.ipv6_src = saddr;
    fib.__bindgen_anon_4.ipv6_dst = daddr;
    fib.__bindgen_anon_1.tot_len = tot_len;
    fib.ifindex = ifindex;

    unsafe {
        bpf_fib_lookup(
            ctx.ctx as *mut _,
            fib,
            core::mem::size_of_val(fib) as i32,
            0, // perform standard lookup (ip route get)
        )
    }
}

#[inline(always)]
pub fn get_fib_macs(
    ctx: &XdpContext,
    src_ip: &IpAddr,
    dst_ip: &IpAddr,
    proto: IpProto,
    tot_len: u16,
    ingress_ifindex: u32,
) -> Option<FibMacs> {
    let mut fib: bpf_fib_lookup = unsafe { core::mem::zeroed() };

    let rc = match (src_ip, dst_ip) {
        (IpAddr::V4(src_ipv4), IpAddr::V4(dst_ipv4)) => {
            // // lookup requires network order for IP addresses
            let src_ip = u32::to_be(src_ipv4.to_bits());
            let dst_ip = u32::to_be(dst_ipv4.to_bits());
            do_fib_lookup(
                ctx,
                &mut fib,
                proto as u8,
                src_ip,
                dst_ip,
                tot_len,
                ingress_ifindex,
            )
        }
        (IpAddr::V6(src_ipv6), IpAddr::V6(dst_ipv6)) => {
            let src_ip = u128_to_u324(u128::to_be(src_ipv6.to_bits()));
            let dst_ip = u128_to_u324(u128::to_be(dst_ipv6.to_bits()));
            do_fib_lookup6(
                ctx,
                &mut fib,
                proto as u8,
                src_ip,
                dst_ip,
                tot_len,
                ingress_ifindex,
            )
        }
        _ => return None,
    };

    if rc != 0 {
        return None;
    }

    Some(FibMacs::new(fib.smac, fib.dmac))
}

#[inline(always)]
pub unsafe fn rewrite_macs(eth_src_addr: *mut [u8; 6], eth_dst_addr: *mut [u8; 6], fib: FibMacs) {
    unsafe {
        core::ptr::copy_nonoverlapping(&fib.src_mac() as *const [u8; 6], eth_src_addr, 1);
        core::ptr::copy_nonoverlapping(&fib.dst_mac() as *const [u8; 6], eth_dst_addr, 1);
    }
}

#[inline(always)]
pub fn route_packet_l2(
    ctx: &XdpContext,
    src_ip: &IpAddr,
    dst_ip: &IpAddr,
    proto: IpProto,
    tot_len: u16,
    ingress_ifindex: u32,
) -> Result<u32, ()> {
    debug!(
        ctx,
        "routing packet {:i} -> {:i} with tot len {}", *src_ip, *dst_ip, tot_len
    );

    let ethh = ptr_at_mut::<EthHdr>(ctx, 0)?;

    let fib = match get_fib_macs(ctx, src_ip, dst_ip, proto, tot_len, ingress_ifindex) {
        Some(fib) => fib,
        None => return Ok(xdp_action::XDP_PASS),
    };

    debug!(
        ctx,
        "fib success result: src mac: {:mac} -> dst mac: {:mac}",
        fib.src_mac(),
        fib.dst_mac()
    );

    unsafe {
        rewrite_macs(
            (*ethh).src_addr.as_mut_ptr() as *mut [u8; 6],
            (*ethh).dst_addr.as_mut_ptr() as *mut [u8; 6],
            fib,
        );
    }
    if ingress_ifindex as usize == ctx.ingress_ifindex() {
        debug!(ctx, "ifindex from fib is the same, xdp_tx'ing packet");
        return Ok(xdp_action::XDP_TX);
    }

    // TODO: support multiple physical interfaces
    Ok(xdp_action::XDP_PASS)
}
