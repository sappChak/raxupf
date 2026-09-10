use core::net::Ipv4Addr;

use aya_ebpf::{
    bindings::{BPF_FIB_LOOKUP_OUTPUT, bpf_fib_lookup, xdp_action},
    helpers::{bpf_fib_lookup, generated::bpf_xdp_adjust_head},
    programs::XdpContext,
};
use network_types::{
    eth::EthHdr,
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};
use raxupf_common::FibMacs;

use crate::{
    AF_INET, GTPU_DST_PORT,
    gtpu::{GtpuExtensionType, GtpuHdr, GtpuMessageType, GtpuOptFields},
    helpers::{csum_replace4, ipv4_csum, ptr_at, ptr_at_mut},
    pdu::{DLPduSession, GtpuDLPduExtensionHdr},
};

pub const GTPU_EXT_LEN: usize = GtpuOptFields::LEN + GtpuDLPduExtensionHdr::LEN;
pub const GTPU_HDR_LEN: usize = GtpuHdr::LEN + GTPU_EXT_LEN;
pub const OUTER_HDRS_LEN_SUM: usize = Ipv4Hdr::LEN + UdpHdr::LEN + GTPU_HDR_LEN;

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
            BPF_FIB_LOOKUP_OUTPUT, // perform lookup from egress perspective (default is ingress)
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
        return None;
    }

    Some(FibMacs {
        src_mac: fib.smac,
        dst_mac: fib.dmac,
    })
}

#[inline(always)]
pub unsafe fn rewrite_macs(eth_src_addr: *mut [u8; 6], eth_dst_addr: *mut [u8; 6], fib: FibMacs) {
    unsafe {
        core::ptr::copy_nonoverlapping(&fib.src_mac as *const [u8; 6], eth_src_addr, 1);
        core::ptr::copy_nonoverlapping(&fib.dst_mac as *const [u8; 6], eth_dst_addr, 1);
    }
}

pub fn route_packet_l2(
    ctx: &XdpContext,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    proto: IpProto,
    tot_len: u16,
    ingress_ifindex: u32,
) -> Result<u32, ()> {
    let ethh: &mut EthHdr = unsafe { &mut *ptr_at_mut(ctx, 0)? };

    let fib = if let Some(fib) = get_fib_macs(ctx, src_ip, dst_ip, proto, tot_len, ingress_ifindex)
    {
        fib
    } else {
        return Ok(xdp_action::XDP_PASS);
    };

    unsafe {
        rewrite_macs(
            ethh.src_addr.as_mut_ptr() as *mut [u8; 6],
            ethh.dst_addr.as_mut_ptr() as *mut [u8; 6],
            fib,
        );
    }
    if ingress_ifindex as usize == ctx.ingress_ifindex() {
        return Ok(xdp_action::XDP_TX);
    }
    // TODO: support multiple physical interfaces
    Ok(xdp_action::XDP_PASS)
}

pub fn encapsulate_into_gtpu(
    ctx: &XdpContext,
    src_addr: Ipv4Addr,
    dst_addr: Ipv4Addr,
    dscp: u8,
    qfi: u8,
    teid: u32,
) -> Result<u16, ()> {
    let oiph: &Ipv4Hdr = unsafe { &*ptr_at(ctx, EthHdr::LEN)? };
    let oiph_len = oiph.tot_len();

    // make room for outer headers
    let result = unsafe { bpf_xdp_adjust_head(ctx.ctx, -(OUTER_HDRS_LEN_SUM as i32)) };
    if result < 0 {
        return Err(());
    }

    let oeth: *mut EthHdr = ptr_at_mut(ctx, OUTER_HDRS_LEN_SUM)?;
    let neth: *const EthHdr = ptr_at(ctx, 0)?;

    unsafe {
        core::ptr::copy_nonoverlapping(neth, oeth, 1);
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

pub fn update_gtpu(ctx: &XdpContext, upf_ipv4: Ipv4Addr, remote_ipv4: Ipv4Addr) -> Result<u16, ()> {
    // change outer source and destination ip addresses, recalcute the checksum
    let iph: &mut Ipv4Hdr = unsafe { &mut *ptr_at_mut(ctx, EthHdr::LEN)? };
    let csum = iph.checksum();
    let new_cs = csum_replace4(csum as u32, iph.src_addr().to_bits(), upf_ipv4.to_bits());
    iph.set_src_addr(upf_ipv4);
    iph.set_checksum(new_cs);

    let csum = iph.checksum();
    let new_cs = csum_replace4(csum as u32, iph.dst_addr().to_bits(), remote_ipv4.to_bits());
    iph.set_dst_addr(remote_ipv4);
    iph.set_checksum(new_cs);

    Ok(iph.tot_len())
}

pub fn decapsulate_gtpu(ctx: &XdpContext, ext_len: usize) -> Result<u16, ()> {
    let encap_size = Ipv4Hdr::LEN + UdpHdr::LEN + GtpuHdr::LEN + ext_len;
    let oeth: *const EthHdr = ptr_at(ctx, 0)?;
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
    let len = iph.tot_len();
    Ok(len)
}

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

fn initialize_udp_header(udph: &mut UdpHdr, src_port: u16, dst_port: u16, len: u16) {
    udph.set_src_port(src_port);
    udph.set_dst_port(dst_port);
    udph.set_len(len);
    udph.set_checksum(0); // TODO: calculate checksum
}

fn initialize_gtpu_header(gtpuh: &mut GtpuHdr, teid: u32, len: u16) {
    gtpuh.set_version(1);
    gtpuh.set_message_type(GtpuMessageType::GPdu.into());
    gtpuh.set_message_length(len);
    gtpuh.set_teid(teid);
}

fn initialize_gtpu_opt_fields(opth: &mut GtpuOptFields) {
    opth.set_sequence_number(0);
    opth.set_npdu_number(0);
    opth.set_next_extension_header(GtpuExtensionType::PduSessionContainer.into());
}

fn initialize_dl_pdu_container(pduh: &mut GtpuDLPduExtensionHdr, qfi: u8) {
    pduh.set_length(0);

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
