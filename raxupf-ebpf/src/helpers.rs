use core::{mem, net::Ipv4Addr};

use aya_ebpf::{
    bindings::{bpf_fib_lookup, xdp_action},
    helpers::{bpf_fib_lookup, generated::bpf_csum_diff},
    programs::XdpContext,
};
use aya_log_ebpf::debug;
use network_types::{
    eth::EthHdr,
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};
use raxupf_common::fib::FibMacs;

use crate::{
    AF_INET,
    gtpu::OUTER_HDRS_LEN_SUM,
    parser::{ParsedIpv4, ParsedPorts},
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
pub unsafe fn parse_l3_l4_headers(
    ctx: &XdpContext,
    iph: *mut Ipv4Hdr,
    offset: usize,
) -> Result<(ParsedIpv4, Option<ParsedPorts>), ()> {
    let (proto, ports) = match unsafe { (*iph).proto() } {
        Ok(IpProto::Udp) => {
            let udph = ptr_at::<UdpHdr>(ctx, offset + Ipv4Hdr::LEN)?;
            let ports = unsafe { ParsedPorts::new((*udph).src_port(), (*udph).dst_port()) };
            (IpProto::Udp, Some(ports))
        }
        Ok(IpProto::Tcp) => {
            let tcph = ptr_at::<TcpHdr>(ctx, offset + Ipv4Hdr::LEN)?;
            let ports = unsafe {
                ParsedPorts::new(
                    u16::from_be_bytes((*tcph).source),
                    u16::from_be_bytes((*tcph).dest),
                )
            };
            (IpProto::Tcp, Some(ports))
        }
        Ok(IpProto::Icmp) => (IpProto::Icmp, None),
        Ok(_) | Err(_) => {
            debug!(ctx, "either unsupported or unknown L4 protocol");
            return Err(());
        }
    };

    unsafe {
        Ok((
            ParsedIpv4::new(
                (*iph).src_addr(),
                (*iph).dst_addr(),
                proto,
                (*iph).tot_len() as usize,
            ),
            ports,
        ))
    }
}

#[inline(always)]
pub fn parse_inner_headers(ctx: &XdpContext) -> Result<(ParsedIpv4, Option<ParsedPorts>), ()> {
    let offset = EthHdr::LEN + OUTER_HDRS_LEN_SUM;
    let inner_ipv4 = ptr_at::<Ipv4Hdr>(ctx, offset)?;
    unsafe { parse_l3_l4_headers(ctx, inner_ipv4 as *mut Ipv4Hdr, offset) }
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
pub fn get_fib_macs(
    ctx: &XdpContext,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    proto: IpProto,
    tot_len: u16,
    ingress_ifindex: u32,
) -> Option<FibMacs> {
    // lookup requires network order for IP addresses
    let src_ip = u32::to_be(src_ip.to_bits());
    let dst_ip = u32::to_be(dst_ip.to_bits());

    let mut fib: bpf_fib_lookup = unsafe { core::mem::zeroed() };

    let rc = do_fib_lookup(
        ctx,
        &mut fib,
        proto as u8,
        src_ip,
        dst_ip,
        tot_len,
        ingress_ifindex,
    );

    if rc != 0 {
        debug!(
            ctx,
            "fib lookup failed for src_ip: {}, dst_ip: {}, proto: {}, tot_len: {}, ingress_ifindex: {}, rc: {}",
            src_ip,
            dst_ip,
            proto as u8,
            tot_len,
            ingress_ifindex,
            rc
        );
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
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    proto: IpProto,
    tot_len: u16,
    ingress_ifindex: u32,
) -> Result<u32, ()> {
    debug!(
        ctx,
        "routing packet {:i} -> {:i} with tot len {}", src_ip, dst_ip, tot_len
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
