use core::{mem, net::Ipv4Addr};

use aya_ebpf::{helpers::generated::bpf_xdp_adjust_head, programs::XdpContext};
use network_types::{
    eth::EthHdr,
    getter_be,
    ip::{IpProto, Ipv4Hdr},
    setter_be,
    udp::UdpHdr,
};

use crate::{
    GTPU_DST_PORT,
    helpers::{csum_replace4, ipv4_csum, ptr_at, ptr_at_mut},
    pdu::{DLPduSession, GtpuDLPduExtensionHdr},
};

pub const GTPU_EXT_LEN: usize = GtpuOptFields::LEN + GtpuDLPduExtensionHdr::LEN;
pub const GTPU_HDR_LEN: usize = GtpuHdr::LEN + GTPU_EXT_LEN;
pub const OUTER_HDRS_LEN_SUM: usize = Ipv4Hdr::LEN + UdpHdr::LEN + GTPU_HDR_LEN;

#[repr(C)]
pub struct GtpuHdr {
    v_pt_flags: u8,
    msg_type: u8,
    msg_len: [u8; 2],
    teid: [u8; 4],
}

#[repr(C)]
pub struct GtpuOptFields {
    seq_number: [u8; 2],
    npdu_num: u8,
    next_ext_hdr_type: u8,
}

// Table 6.1-1, 3GPP TS 29.281 Rel 17
#[derive(Debug)]
pub enum GtpuMessageType {
    EchoRequest = 1,
    EchoResponse = 2,
    ErrorIndication = 26,
    SupportedExtensionHeaders = 31,
    TunnelStatus = 253,
    EndMarker = 254,
    GPdu = 255,
}

impl From<GtpuMessageType> for u8 {
    fn from(val: GtpuMessageType) -> Self {
        match val {
            GtpuMessageType::EchoRequest => 1,
            GtpuMessageType::EchoResponse => 2,
            GtpuMessageType::ErrorIndication => 26,
            GtpuMessageType::SupportedExtensionHeaders => 31,
            GtpuMessageType::TunnelStatus => 253,
            GtpuMessageType::EndMarker => 254,
            GtpuMessageType::GPdu => 255,
        }
    }
}

impl TryFrom<u8> for GtpuMessageType {
    type Error = u8;

    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        match byte {
            1 => Ok(Self::EchoRequest),
            2 => Ok(Self::EchoResponse),
            26 => Ok(Self::ErrorIndication),
            31 => Ok(Self::SupportedExtensionHeaders),
            253 => Ok(Self::TunnelStatus),
            254 => Ok(Self::EndMarker),
            255 => Ok(Self::GPdu),
            _ => Err(byte),
        }
    }
}

// Figure 5.2.1-3, 3GPP TS 29.281 Rel 17 (not all of them)
pub enum GtpuExtensionType {
    NoMoreExtensions = 0x00,
    UdpPort = 0x40,
    PduSessionContainer = 0x85,
}

impl From<GtpuExtensionType> for u8 {
    fn from(val: GtpuExtensionType) -> Self {
        match val {
            GtpuExtensionType::NoMoreExtensions => 0x00,
            GtpuExtensionType::UdpPort => 0x40,
            GtpuExtensionType::PduSessionContainer => 0x85,
        }
    }
}

impl TryFrom<u8> for GtpuExtensionType {
    type Error = u8;

    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        match byte {
            0x00 => Ok(Self::NoMoreExtensions),
            0x40 => Ok(Self::UdpPort),
            0x85 => Ok(Self::PduSessionContainer),
            _ => Err(byte),
        }
    }
}

impl GtpuHdr {
    pub const LEN: usize = mem::size_of::<GtpuHdr>();

    /// Gets the 3-bit Version value.
    #[inline]
    pub fn version(&self) -> u8 {
        (self.v_pt_flags & 0xE0) >> 5
    }

    /// Sets the 3-bit Version value.
    /// Input `version` should be a 3-bit integer (0-7)
    #[inline]
    pub fn set_version(&mut self, version: u8) {
        let preserved_bits = self.v_pt_flags & 0x1F;
        self.v_pt_flags = ((version & 0x07) << 5) | preserved_bits;
    }

    /// Gets the 1-bit Protocol Type (PT) value.
    #[inline]
    pub fn protocol_type(&self) -> u8 {
        (self.v_pt_flags & 0x10) >> 4
    }

    /// Sets the 1-bit Protocol Type (PT) value.
    /// Input `pt` should be 0 or 1
    #[inline]
    pub fn set_protocol_type(&mut self, pt: u8) {
        let preserved_bits = self.v_pt_flags & 0xEF;
        self.v_pt_flags = (pt << 4) | preserved_bits;
    }

    #[inline]
    pub fn has_flags(&self) -> bool {
        self.v_pt_flags & 0x07 != 0
    }

    #[inline]
    pub fn has_extension_header(&self) -> bool {
        (self.v_pt_flags & 0x04) != 0
    }

    /// Sets the 1-bit Extension Header (E) value.
    /// Input `e` should be 0 or 1
    #[inline]
    pub fn set_extension_header(&mut self, e: u8) {
        let preserved_bits = self.v_pt_flags & 0xFB;
        self.v_pt_flags = (e << 2) | preserved_bits;
    }

    #[inline]
    pub fn has_sequence_number(&self) -> bool {
        (self.v_pt_flags & 0x02) != 0
    }

    #[inline]
    pub fn has_npdu_number(&self) -> bool {
        (self.v_pt_flags & 0x01) != 0
    }

    /// Gets the 8-bit Message Type value.
    #[inline]
    pub fn message_type(&self) -> Result<GtpuMessageType, u8> {
        match GtpuMessageType::try_from(self.msg_type) {
            Ok(t) => Ok(t),
            Err(e) => Err(e),
        }
    }

    /// Sets the 8-bit Message Type value.
    #[inline]
    pub fn set_message_type(&mut self, message_type: u8) {
        self.msg_type = message_type;
    }

    /// Gets the Message Length in Host Byte Order
    #[inline]
    pub fn message_length(&self) -> u16 {
        // SAFETY: Pointer arithmetic in bounds of the struct
        unsafe { getter_be!(self, msg_len, u16) }
    }

    /// Sets the Message Length in Network Byte Order
    #[inline]
    pub fn set_message_length(&mut self, message_length: u16) {
        // SAFETY: Pointer arithmetic in bounds of the struct
        unsafe { setter_be!(self, msg_len, message_length) };
    }

    /// Gets the Tunnel Endpoint Identifier (TEID) in Host Byte Order
    #[inline]
    pub fn teid(&self) -> u32 {
        // SAFETY: Pointer arithmetic in bounds of the struct
        unsafe { getter_be!(self, teid, u32) }
    }

    /// Sets the Tunnel Endpoint Identifier (TEID) in Network Byte Order
    #[inline]
    pub fn set_teid(&mut self, teid: u32) {
        // SAFETY: Pointer arithmetic in bounds of the struct
        unsafe { setter_be!(self, teid, teid) };
    }
}

impl GtpuOptFields {
    pub const LEN: usize = mem::size_of::<GtpuOptFields>();

    pub fn sequence_number(&self) -> u32 {
        unsafe { getter_be!(self, seq_number, u32) }
    }

    pub fn set_sequence_number(&mut self, seq_number: u32) {
        unsafe { setter_be!(self, seq_number, seq_number) }
    }

    pub fn npdu_number(&self) -> u8 {
        self.npdu_num
    }

    pub fn set_npdu_number(&mut self, npdu: u8) {
        self.npdu_num = npdu;
    }

    pub fn set_next_extension_header(&mut self, next_ext_hdr_type: u8) {
        self.next_ext_hdr_type = next_ext_hdr_type;
    }

    pub fn next_extension_header_type(&self) -> Result<GtpuExtensionType, u8> {
        match GtpuExtensionType::try_from(self.next_ext_hdr_type) {
            Ok(t) => Ok(t),
            Err(e) => Err(e),
        }
    }
}

pub fn encapsulate_into_gtpu(
    ctx: &XdpContext,
    src_addr: Ipv4Addr,
    dst_addr: Ipv4Addr,
    dscp: u8,
    qfi: u8,
    teid: u32,
) -> Result<u16, ()> {
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

#[inline(always)]
pub fn decapsulate_gtpu(ctx: &XdpContext, ext_len: usize) -> Result<u16, ()> {
    let oeth: *const EthHdr = ptr_at(ctx, 0)?;

    let encap_size = Ipv4Hdr::LEN + UdpHdr::LEN + GtpuHdr::LEN + ext_len;
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
    Ok(iph.tot_len())
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
