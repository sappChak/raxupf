use core::mem;

use crate::{
    gtpu_helpers::OUTER_HDRS_LEN_SUM,
    parser::{ParsedIpv4, ParsedPorts},
};
use aya_ebpf::{helpers::generated::bpf_csum_diff, programs::XdpContext};
use aya_log_ebpf::debug;
use network_types::{
    eth::EthHdr,
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
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
pub fn parse_l3_l4_headers(
    ctx: &XdpContext,
    iph: &Ipv4Hdr,
    offset: usize,
) -> Result<(ParsedIpv4, Option<ParsedPorts>), ()> {
    let (proto, ports) = match iph.proto() {
        Ok(IpProto::Udp) => {
            let udph: &UdpHdr = unsafe { &*ptr_at(ctx, offset + Ipv4Hdr::LEN)? };
            let ports = ParsedPorts::new(udph.src_port(), udph.dst_port());
            (IpProto::Udp, Some(ports))
        }
        Ok(IpProto::Tcp) => {
            let tcph: &TcpHdr = unsafe { &*ptr_at(ctx, offset + Ipv4Hdr::LEN)? };
            let ports = ParsedPorts::new(
                u16::from_be_bytes(tcph.source),
                u16::from_be_bytes(tcph.dest),
            );
            (IpProto::Udp, Some(ports))
        }
        Ok(IpProto::Icmp) => (IpProto::Icmp, None),
        Ok(_) | Err(_) => {
            debug!(ctx, "either unsupported or unknow L4 protocol");
            return Err(());
        }
    };

    Ok((
        ParsedIpv4::new(
            iph.src_addr(),
            iph.dst_addr(),
            proto,
            iph.tot_len() as usize,
        ),
        ports,
    ))
}

#[inline(always)]
pub fn parse_inner_headers(ctx: &XdpContext) -> Result<(ParsedIpv4, Option<ParsedPorts>), ()> {
    let offset = EthHdr::LEN + OUTER_HDRS_LEN_SUM;
    let inner_ipv4: &Ipv4Hdr = unsafe { &*ptr_at(ctx, offset)? };
    parse_l3_l4_headers(ctx, inner_ipv4, offset)
}
