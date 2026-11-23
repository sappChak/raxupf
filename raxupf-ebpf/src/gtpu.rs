use core::net::{IpAddr, Ipv4Addr};

use aya_ebpf::{helpers::generated::bpf_xdp_adjust_head, programs::XdpContext};
use network_types::{
    eth::EthHdr,
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};
use raxupf_common::gtpu::{
    DLPduSession, GTPU_DST_PORT, GTPU_EXT_LEN, GTPU_HDR_LEN, GtpuDLPduExtensionHdr,
    GtpuExtensionType, GtpuHdr, GtpuMessageType, GtpuOptFields, OUTER_HDRS_LEN_SUM,
};

use crate::helpers::{csum_replace4, ipv4_csum, ptr_at, ptr_at_mut};

#[inline(always)]
pub fn encapsulate_into_gtpu(
    ctx: &XdpContext,
    src_addr: &IpAddr,
    dst_addr: &IpAddr,
    dscp: u8,
    qfi: u8,
    teid: u32,
) -> Result<u16, ()> {
    let (src_addr, dst_addr) = match (src_addr, dst_addr) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => (*src, *dst),
        _ => return Err(()), // TODO: implement Ipv6
    };
    let oiph = ptr_at::<Ipv4Hdr>(ctx, EthHdr::LEN)?;
    let oiph_len = unsafe { (*oiph).tot_len() };

    // make room for outer headers
    let result = unsafe { bpf_xdp_adjust_head(ctx.ctx, -(OUTER_HDRS_LEN_SUM as i32)) };
    if result < 0 {
        return Err(());
    }

    let oeth: *const EthHdr = ptr_at(ctx, OUTER_HDRS_LEN_SUM)?;
    let neth: *mut EthHdr = ptr_at_mut(ctx, 0)?;

    unsafe {
        core::ptr::copy_nonoverlapping(oeth, neth, 1);
    }

    let iph: &mut Ipv4Hdr = unsafe { &mut *ptr_at_mut(ctx, EthHdr::LEN)? };
    // All L3+ outer headers + old IP header is the new IP header length
    let niph_len = (OUTER_HDRS_LEN_SUM as u16) + oiph_len;
    initialize_ipv4_header(iph, src_addr, dst_addr, IpProto::Udp, dscp, niph_len);

    let udph: &mut UdpHdr = unsafe { &mut *ptr_at_mut(ctx, EthHdr::LEN + Ipv4Hdr::LEN)? };
    // GTP-U header + old IP header is the UDP payload
    let nudh_len = ((UdpHdr::LEN + GTPU_HDR_LEN) as u16) + oiph_len;
    initialize_udp_header(udph, GTPU_DST_PORT, GTPU_DST_PORT, nudh_len);

    let gtpuh: &mut GtpuHdr =
        unsafe { &mut *ptr_at_mut(ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN)? };
    // GTP-U Extension Header + old IP header is the GTP-U payload
    let ngtph_len = GTPU_EXT_LEN as u16 + oiph_len;
    initialize_gtpu_header(gtpuh, teid, ngtph_len);

    let opth: &mut GtpuOptFields =
        unsafe { &mut *ptr_at_mut(ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + GtpuHdr::LEN)? };
    initialize_gtpu_opt_fields(opth);

    let pduh: &mut GtpuDLPduExtensionHdr = unsafe {
        &mut *ptr_at_mut(
            ctx,
            EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + GtpuHdr::LEN + GtpuOptFields::LEN,
        )?
    };
    initialize_dl_pdu_container(pduh, qfi);

    let csum = unsafe {
        ipv4_csum(
            iph as *mut Ipv4Hdr as *mut u32,
            core::mem::size_of::<Ipv4Hdr>() as u32,
        )
    };
    iph.set_checksum(csum);

    Ok(iph.tot_len())
}

#[inline(always)]
pub fn update_gtpu(
    ctx: &XdpContext,
    upf_ip: &IpAddr,
    remote_ip: &IpAddr,
    teid: u32,
) -> Result<u16, ()> {
    let (upf_ip, remote_ip) = match (upf_ip, remote_ip) {
        (IpAddr::V4(upf), IpAddr::V4(remote)) => (*upf, *remote),
        _ => return Err(()), // TODO: implement Ipv6
    };
    // change outer source and destination ip addresses, recalcute the checksum
    let iph: &mut Ipv4Hdr = unsafe { &mut *ptr_at_mut(ctx, EthHdr::LEN)? };
    let csum = iph.checksum();
    let new_cs = csum_replace4(csum as u32, iph.src_addr().to_bits(), upf_ip.to_bits());
    iph.set_src_addr(upf_ip);
    iph.set_checksum(new_cs);

    let csum = iph.checksum();
    let new_cs = csum_replace4(csum as u32, iph.dst_addr().to_bits(), remote_ip.to_bits());
    iph.set_dst_addr(remote_ip);
    iph.set_checksum(new_cs);

    let gtpuh: &mut GtpuHdr =
        unsafe { &mut *ptr_at_mut(ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN)? };
    gtpuh.set_teid(teid);

    Ok(iph.tot_len())
}

#[inline(always)]
pub fn decapsulate_gtpu(ctx: &XdpContext, psc_len: usize) -> Result<(u16, IpProto), ()> {
    let oeth: *const EthHdr = ptr_at(ctx, 0)?;

    let encap_size = Ipv4Hdr::LEN + UdpHdr::LEN + GtpuHdr::LEN + GtpuOptFields::LEN + psc_len;
    if !(8..=1500).contains(&encap_size) {
        return Err(());
    }
    let neth: *mut EthHdr = ptr_at_mut(ctx, encap_size)?;

    unsafe {
        core::ptr::copy_nonoverlapping(oeth, neth, 1);
    }

    unsafe {
        if bpf_xdp_adjust_head(ctx.ctx, encap_size as i32) != 0 {
            return Err(());
        }
    };

    let iph: &Ipv4Hdr = unsafe { &*ptr_at(ctx, EthHdr::LEN)? };
    Ok((iph.tot_len(), iph.proto().map_err(|_| ())?))
}

#[inline(always)]
fn initialize_ipv4_header(
    iph: &mut Ipv4Hdr,
    src_addr: Ipv4Addr,
    dst_addr: Ipv4Addr,
    proto: IpProto,
    dscp: u8,
    tot_len: u16,
) {
    let (version, ihl_in_bytes) = (4, 5 * 4);
    iph.set_vihl(version, ihl_in_bytes);
    let ecn = 0; // TODO:
    iph.set_tos(dscp, ecn);
    iph.set_tot_len(tot_len);
    iph.set_id(0);
    let (flags, offset) = (4, 0); // 0x4000 flag - DON'T fragment
    iph.set_frags(flags, offset);
    iph.ttl = 64;
    iph.set_proto(proto);
    iph.set_checksum(0);
    iph.set_src_addr(src_addr);
    iph.set_dst_addr(dst_addr);
}

#[inline(always)]
fn initialize_udp_header(udph: &mut UdpHdr, src_port: u16, dst_port: u16, len: u16) {
    udph.set_src_port(src_port);
    udph.set_dst_port(dst_port);
    udph.set_len(len);
    udph.set_checksum(0); // TODO: calculate checksum
}

#[inline(always)]
fn initialize_gtpu_header(gtpuh: &mut GtpuHdr, teid: u32, len: u16) {
    gtpuh.set_version(1);
    gtpuh.set_message_type(GtpuMessageType::GPdu.into());
    gtpuh.set_message_length(len);
    gtpuh.set_teid(teid);
}

#[inline(always)]
fn initialize_gtpu_opt_fields(opth: &mut GtpuOptFields) {
    opth.set_sequence_number(0);
    opth.set_npdu_number(0);
    opth.set_next_extension_header(GtpuExtensionType::PduSessionContainer.into());
}

#[inline(always)]
fn initialize_dl_pdu_container(pduh: &mut GtpuDLPduExtensionHdr, qfi: u8) {
    pduh.set_length(0); // ?

    let mut content = DLPduSession::default();
    content.set_pdu_type(0); // 0 - DL PDU
    content.set_qmp(0);
    content.set_snp(0);
    content.set_msnp(0);
    content.set_ppp(0);
    content.set_rqi(0);
    content.set_qfi(qfi);

    pduh.set_content(content);
    pduh.set_next_extension_header(0); // no more extension headers
}
