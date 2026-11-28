//! GTP-U header (3GPP TS 29.281) and PDU Session Container (3GPP TS 38.415)
//! wire-format structs.
//!
//! Accessor conventions used throughout this module:
//! - Single-bit flags are `bool`: `has_x()` reads the flag, `set_x(bool)` writes it.
//! - Multi-bit fields are `u8`: `x()` reads the value, `set_x(u8)` writes it and
//!   returns `Err(())` (leaving the header unchanged) if the value does not fit
//!   in the field's width.
//! - Every setter only touches its own bits; all other bits are preserved.

use core::mem;

use network_types::{getter_be, ip::Ipv4Hdr, setter_be, udp::UdpHdr};

pub const GTPU_PORT: u16 = 2152; // per 3GPP TS 29.281 Rel 17
pub const GTP_PROTOCOL_TYPE: u8 = 1; // Distinguish between GTP' and GTP
pub const GTP_VERSION: u8 = 1; // GTP-U is Version 1
pub const DL_PDU_TYPE: u8 = 0; // DL PDU SESSION INFORMATION, TS 38.415
pub const UL_PDU_TYPE: u8 = 1; // UL PDU SESSION INFORMATION, TS 38.415

pub const GTPU_EXT_LEN: usize = GtpuOptFields::LEN + GtpuDLPduExtensionHdr::LEN;
pub const GTPU_HDR_LEN: usize = GtpuHdr::LEN + GTPU_EXT_LEN;
pub const OUTER_HDRS_LEN_SUM: usize = Ipv4Hdr::LEN + UdpHdr::LEN + GTPU_HDR_LEN;

/// Mask of the 4-bit PDU Type in the first octet of a PDU Session Information frame.
const PDU_TYPE_MASK: u8 = 0xF0;
/// Mask of the 6-bit QFI in the second octet of a PDU Session Information frame.
const QFI_MASK: u8 = 0x3F;

/// Mandatory part of the GTP-U header, Figure 5.1-1, 3GPP TS 29.281.
///
/// First octet: | Version (3) | PT (1) | Spare (1) | E (1) | S (1) | PN (1) |
#[repr(C)]
#[derive(Default)]
pub struct GtpuHdr {
    v_pt_flags: u8,
    msg_type: u8,
    msg_len: [u8; 2],
    teid: [u8; 4],
}

/// Optional fields present when any of E, S or PN is set, Figure 5.1-1, 3GPP TS 29.281.
#[repr(C)]
#[derive(Default)]
pub struct GtpuOptFields {
    seq_number: [u8; 2],
    npdu_num: u8,
    next_ext_hdr_type: u8,
}

// Table 6.1-1, 3GPP TS 29.281 Rel 17
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
        val as u8
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
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GtpuExtensionType {
    NoMoreExtensions = 0x00,
    UdpPort = 0x40,
    PduSessionContainer = 0x85,
}

impl From<GtpuExtensionType> for u8 {
    fn from(val: GtpuExtensionType) -> Self {
        val as u8
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

/// Writes `value` into the bits selected by `mask` (with `shift` being the
/// position of the mask's lowest bit), preserving all other bits of `byte`.
/// Returns `Err(())` and leaves `byte` unchanged if `value` does not fit.
#[inline(always)]
fn set_bits(byte: &mut u8, mask: u8, shift: u32, value: u8) -> Result<(), ()> {
    if value > (mask >> shift) {
        return Err(());
    }
    *byte = (*byte & !mask) | (value << shift);
    Ok(())
}

/// Sets or clears the bits selected by `mask`, preserving all other bits.
#[inline(always)]
fn set_flag(byte: &mut u8, mask: u8, value: bool) {
    if value {
        *byte |= mask;
    } else {
        *byte &= !mask;
    }
}

impl GtpuHdr {
    pub const LEN: usize = mem::size_of::<GtpuHdr>();

    const VERSION_MASK: u8 = 0xE0;
    const PT_MASK: u8 = 0x10;
    const E_MASK: u8 = 0x04;
    const S_MASK: u8 = 0x02;
    const PN_MASK: u8 = 0x01;

    #[inline]
    pub fn new(teid: u32, len: u16) -> Result<Self, ()> {
        let mut gtpuh = GtpuHdr::default();
        gtpuh.set_version(GTP_VERSION)?;
        gtpuh.set_message_type(GtpuMessageType::GPdu.into());
        gtpuh.set_message_length(len);
        gtpuh.set_protocol_type(GTP_PROTOCOL_TYPE)?;
        gtpuh.set_extension_header(true);
        gtpuh.set_teid(teid);
        Ok(gtpuh)
    }

    /// Gets the 3-bit Version value.
    #[inline]
    pub fn version(&self) -> u8 {
        (self.v_pt_flags & Self::VERSION_MASK) >> 5
    }

    /// Sets the 3-bit Version value. Fails if `version` > 7.
    #[inline]
    pub fn set_version(&mut self, version: u8) -> Result<(), ()> {
        set_bits(&mut self.v_pt_flags, Self::VERSION_MASK, 5, version)
    }

    /// Gets the 1-bit Protocol Type (PT) value: 1 for GTP, 0 for GTP'.
    #[inline]
    pub fn protocol_type(&self) -> u8 {
        (self.v_pt_flags & Self::PT_MASK) >> 4
    }

    /// Sets the 1-bit Protocol Type (PT) value. Fails if `pt` > 1.
    #[inline]
    pub fn set_protocol_type(&mut self, pt: u8) -> Result<(), ()> {
        set_bits(&mut self.v_pt_flags, Self::PT_MASK, 4, pt)
    }

    /// True if any of E, S or PN is set, i.e. the optional fields are present.
    #[inline]
    pub fn has_flags(&self) -> bool {
        self.v_pt_flags & (Self::E_MASK | Self::S_MASK | Self::PN_MASK) != 0
    }

    /// Extension Header flag (E).
    #[inline]
    pub fn has_extension_header(&self) -> bool {
        self.v_pt_flags & Self::E_MASK != 0
    }

    /// Sets the Extension Header flag (E).
    #[inline]
    pub fn set_extension_header(&mut self, e: bool) {
        set_flag(&mut self.v_pt_flags, Self::E_MASK, e);
    }

    /// Sequence Number flag (S).
    #[inline]
    pub fn has_sequence_number(&self) -> bool {
        self.v_pt_flags & Self::S_MASK != 0
    }

    /// Sets the Sequence Number flag (S).
    #[inline]
    pub fn set_sequence_number_flag(&mut self, s: bool) {
        set_flag(&mut self.v_pt_flags, Self::S_MASK, s);
    }

    /// N-PDU Number flag (PN).
    #[inline]
    pub fn has_npdu_number(&self) -> bool {
        self.v_pt_flags & Self::PN_MASK != 0
    }

    /// Sets the N-PDU Number flag (PN).
    #[inline]
    pub fn set_npdu_number_flag(&mut self, pn: bool) {
        set_flag(&mut self.v_pt_flags, Self::PN_MASK, pn);
    }

    /// Gets the 8-bit Message Type; unknown types are returned as `Err(raw)`.
    #[inline]
    pub fn message_type(&self) -> Result<GtpuMessageType, u8> {
        GtpuMessageType::try_from(self.msg_type)
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

    #[inline]
    pub fn new() -> Self {
        let mut opth = GtpuOptFields::default();
        opth.set_sequence_number(0);
        opth.set_npdu_number(0);
        opth.set_next_extension_header(GtpuExtensionType::PduSessionContainer.into());
        opth
    }

    /// Gets the Sequence Number in Host Byte Order
    #[inline]
    pub fn sequence_number(&self) -> u16 {
        // SAFETY: Pointer arithmetic in bounds of the struct
        unsafe { getter_be!(self, seq_number, u16) }
    }

    /// Sets the Sequence Number in Network Byte Order
    #[inline]
    pub fn set_sequence_number(&mut self, seq_number: u16) {
        // SAFETY: Pointer arithmetic in bounds of the struct
        unsafe { setter_be!(self, seq_number, seq_number) }
    }

    #[inline]
    pub fn npdu_number(&self) -> u8 {
        self.npdu_num
    }

    #[inline]
    pub fn set_npdu_number(&mut self, npdu: u8) {
        self.npdu_num = npdu;
    }

    /// Gets the Next Extension Header Type; unknown types are returned as `Err(raw)`.
    #[inline]
    pub fn next_extension_header_type(&self) -> Result<GtpuExtensionType, u8> {
        GtpuExtensionType::try_from(self.next_ext_hdr_type)
    }

    #[inline]
    pub fn set_next_extension_header(&mut self, next_ext_hdr_type: u8) {
        self.next_ext_hdr_type = next_ext_hdr_type;
    }
}

/// PDU Session Container extension header carrying DL PDU SESSION INFORMATION,
/// Figure 5.2.1-1, 3GPP TS 29.281.
#[repr(C)]
pub struct GtpuDLPduExtensionHdr {
    length: u8,
    content: DLPduSession,
    next_ext_hdr_type: u8,
}

/// PDU Session Container extension header carrying UL PDU SESSION INFORMATION,
/// Figure 5.2.1-1, 3GPP TS 29.281.
#[repr(C)]
pub struct GtpuULPduExtensionHdr {
    length: u8,
    content: ULPduSession,
    next_ext_hdr_type: u8,
}

impl GtpuULPduExtensionHdr {
    pub const LEN: usize = mem::size_of::<GtpuDLPduExtensionHdr>();

    pub fn new(qfi: u8) -> Result<Self, ()> {
        let mut pduh = GtpuULPduExtensionHdr {
            length: 0,
            content: ULPduSession::default(),
            next_ext_hdr_type: GtpuExtensionType::NoMoreExtensions.into(),
        };
        pduh.set_length(Self::LEN as u8 / 4);
        pduh.content.set_pdu_type(UL_PDU_TYPE)?;
        pduh.content.set_qfi(qfi)?;
        Ok(pduh)
    }

    /// Gets the extension header length in 4-octet units.
    #[inline]
    pub fn length(&self) -> u8 {
        self.length
    }

    /// Sets the extension header length in 4-octet units.
    #[inline]
    pub fn set_length(&mut self, length: u8) {
        self.length = length;
    }

    #[inline]
    pub fn content(&self) -> &ULPduSession {
        &self.content
    }

    #[inline]
    pub fn set_content(&mut self, content: ULPduSession) {
        self.content = content
    }

    /// Gets the Next Extension Header Type; unknown types are returned as `Err(raw)`.
    #[inline]
    pub fn next_extension_header_type(&self) -> Result<GtpuExtensionType, u8> {
        GtpuExtensionType::try_from(self.next_ext_hdr_type)
    }

    #[inline]
    pub fn set_next_extension_header(&mut self, neh_type: u8) {
        self.next_ext_hdr_type = neh_type;
    }
}

/// DL PDU SESSION INFORMATION as per 3GPP TS 38.415
///
/// Octet 1: | PDU Type (4) | QMP | SNP | MSNP | Spare |
/// Octet 2: | PPP | RQI | QFI (6) |
#[repr(C)]
#[derive(Default)]
pub struct DLPduSession {
    pt_flags: u8,
    flags_qfi: u8,
}

/// UL PDU SESSION INFORMATION as per 3GPP TS 38.415
///
/// Octet 1: | PDU Type (4) | flags (4) |
/// Octet 2: | flags (2) | QFI (6) |
#[repr(C)]
#[derive(Default)]
pub struct ULPduSession {
    pt_flags: u8,
    n39di_nie_qfi: u8,
}

impl ULPduSession {
    pub const LEN: usize = mem::size_of::<ULPduSession>();

    /// Gets the 4-bit PDU Type.
    #[inline]
    pub fn pdu_type(&self) -> u8 {
        (self.pt_flags & PDU_TYPE_MASK) >> 4
    }

    /// Sets the 4-bit PDU Type. Fails if `pdu_type` > 15.
    #[inline]
    pub fn set_pdu_type(&mut self, pdu_type: u8) -> Result<(), ()> {
        set_bits(&mut self.pt_flags, PDU_TYPE_MASK, 4, pdu_type)
    }

    /// Gets the 6-bit QoS Flow Identifier.
    #[inline]
    pub fn qfi(&self) -> u8 {
        self.n39di_nie_qfi & QFI_MASK
    }

    /// Sets the 6-bit QoS Flow Identifier. Fails if `qfi` > 63.
    #[inline]
    pub fn set_qfi(&mut self, qfi: u8) -> Result<(), ()> {
        set_bits(&mut self.n39di_nie_qfi, QFI_MASK, 0, qfi)
    }
}

impl GtpuDLPduExtensionHdr {
    pub const LEN: usize = mem::size_of::<GtpuDLPduExtensionHdr>();

    #[inline]
    pub fn new(qfi: u8) -> Result<Self, ()> {
        let mut pduh = GtpuDLPduExtensionHdr {
            length: 0,
            content: DLPduSession::default(),
            next_ext_hdr_type: GtpuExtensionType::NoMoreExtensions.into(),
        };
        pduh.set_length(Self::LEN as u8 / 4);
        pduh.content.set_pdu_type(DL_PDU_TYPE)?;
        pduh.content.set_qfi(qfi)?;
        Ok(pduh)
    }

    /// Gets the extension header length in 4-octet units.
    #[inline]
    pub fn length(&self) -> u8 {
        self.length
    }

    /// Sets the extension header length in 4-octet units.
    #[inline]
    pub fn set_length(&mut self, length: u8) {
        self.length = length;
    }

    #[inline]
    pub fn content(&self) -> &DLPduSession {
        &self.content
    }

    #[inline]
    pub fn set_content(&mut self, content: DLPduSession) {
        self.content = content
    }

    /// Gets the Next Extension Header Type; unknown types are returned as `Err(raw)`.
    #[inline]
    pub fn next_extension_header_type(&self) -> Result<GtpuExtensionType, u8> {
        GtpuExtensionType::try_from(self.next_ext_hdr_type)
    }

    #[inline]
    pub fn set_next_extension_header(&mut self, neh_type: u8) {
        self.next_ext_hdr_type = neh_type;
    }
}

impl DLPduSession {
    pub const LEN: usize = mem::size_of::<DLPduSession>();

    const QMP_MASK: u8 = 0x08;
    const SNP_MASK: u8 = 0x04;
    const MSNP_MASK: u8 = 0x02;
    const PPP_MASK: u8 = 0x80;
    const RQI_MASK: u8 = 0x40;

    /// Gets the 4-bit PDU Type.
    #[inline]
    pub fn pdu_type(&self) -> u8 {
        (self.pt_flags & PDU_TYPE_MASK) >> 4
    }

    /// Sets the 4-bit PDU Type. Fails if `pdu_type` > 15.
    #[inline]
    pub fn set_pdu_type(&mut self, pdu_type: u8) -> Result<(), ()> {
        set_bits(&mut self.pt_flags, PDU_TYPE_MASK, 4, pdu_type)
    }

    /// QoS Monitoring Packet flag (QMP).
    #[inline]
    pub fn has_qmp(&self) -> bool {
        self.pt_flags & Self::QMP_MASK != 0
    }

    #[inline]
    pub fn set_qmp(&mut self, qmp: bool) {
        set_flag(&mut self.pt_flags, Self::QMP_MASK, qmp);
    }

    /// DL Sending Time Stamp Present flag (SNP).
    #[inline]
    pub fn has_snp(&self) -> bool {
        self.pt_flags & Self::SNP_MASK != 0
    }

    #[inline]
    pub fn set_snp(&mut self, snp: bool) {
        set_flag(&mut self.pt_flags, Self::SNP_MASK, snp);
    }

    /// DL MBS QFI Sequence Number Present flag (MSNP).
    #[inline]
    pub fn has_msnp(&self) -> bool {
        self.pt_flags & Self::MSNP_MASK != 0
    }

    #[inline]
    pub fn set_msnp(&mut self, msnp: bool) {
        set_flag(&mut self.pt_flags, Self::MSNP_MASK, msnp);
    }

    /// Paging Policy Presence flag (PPP).
    #[inline]
    pub fn has_ppp(&self) -> bool {
        self.flags_qfi & Self::PPP_MASK != 0
    }

    #[inline]
    pub fn set_ppp(&mut self, ppp: bool) {
        set_flag(&mut self.flags_qfi, Self::PPP_MASK, ppp);
    }

    /// Reflective QoS Indicator flag (RQI).
    #[inline]
    pub fn has_rqi(&self) -> bool {
        self.flags_qfi & Self::RQI_MASK != 0
    }

    #[inline]
    pub fn set_rqi(&mut self, rqi: bool) {
        set_flag(&mut self.flags_qfi, Self::RQI_MASK, rqi);
    }

    /// Gets the 6-bit QoS Flow Identifier.
    #[inline]
    pub fn qfi(&self) -> u8 {
        self.flags_qfi & QFI_MASK
    }

    /// Sets the 6-bit QoS Flow Identifier. Fails if `qfi` > 63.
    #[inline]
    pub fn set_qfi(&mut self, qfi: u8) -> Result<(), ()> {
        set_bits(&mut self.flags_qfi, QFI_MASK, 0, qfi)
    }
}

#[cfg(test)]
mod tests {
    use core::mem;

    use super::*;

    /// View any `#[repr(C)]` header as the raw bytes that would go on the wire.
    fn as_bytes<T>(hdr: &T) -> &[u8] {
        // SAFETY: all headers in this module consist only of `u8`/`[u8; N]`
        // fields, so there is no padding and every byte is initialized.
        unsafe { core::slice::from_raw_parts(hdr as *const T as *const u8, mem::size_of::<T>()) }
    }

    fn gtpu_hdr() -> GtpuHdr {
        GtpuHdr {
            v_pt_flags: 0,
            msg_type: 0,
            msg_len: [0, 0],
            teid: [0, 0, 0, 0],
        }
    }

    fn gtpu_opt_fields() -> GtpuOptFields {
        GtpuOptFields {
            seq_number: [0, 0],
            npdu_num: 0,
            next_ext_hdr_type: 0,
        }
    }

    fn dl_pdu_ext_hdr() -> GtpuDLPduExtensionHdr {
        GtpuDLPduExtensionHdr {
            length: 0,
            content: DLPduSession::default(),
            next_ext_hdr_type: 0,
        }
    }

    // ---------------------------------------------------------------------
    // Sizes (TS 29.281 Figure 5.1-1, TS 38.415 Figure 5.5.2.1-1)
    // ---------------------------------------------------------------------

    #[test]
    fn test_gtpu_hdr_size() {
        // Mandatory part of the GTP-U header is 8 bytes
        assert_eq!(GtpuHdr::LEN, 8);
        assert_eq!(GtpuHdr::LEN, mem::size_of::<GtpuHdr>());
    }

    #[test]
    fn test_gtpu_opt_fields_size() {
        // Sequence Number (2) + N-PDU Number (1) + Next Extension Header Type (1)
        assert_eq!(GtpuOptFields::LEN, 4);
        assert_eq!(GtpuOptFields::LEN, mem::size_of::<GtpuOptFields>());
    }

    #[test]
    fn test_pdu_session_container_size() {
        // Length (1) + DL PDU SESSION INFORMATION (2) + Next Extension Header Type (1)
        assert_eq!(GtpuDLPduExtensionHdr::LEN, 4);
        assert_eq!(DLPduSession::LEN, 2);
        assert_eq!(ULPduSession::LEN, 2);
        assert_eq!(mem::size_of::<GtpuULPduExtensionHdr>(), 4);
        // Extension header length is in 4-octet units and must be a multiple of 4
        assert_eq!(GtpuDLPduExtensionHdr::LEN % 4, 0);
    }

    #[test]
    fn test_combined_lengths() {
        assert_eq!(GTPU_EXT_LEN, 8);
        assert_eq!(GTPU_HDR_LEN, 16);
        // IPv4 (20) + UDP (8) + GTP-U with PDU Session Container (16)
        assert_eq!(OUTER_HDRS_LEN_SUM, 44);
    }

    // ---------------------------------------------------------------------
    // Bit helpers
    // ---------------------------------------------------------------------

    #[test]
    fn test_set_bits() {
        let mut byte = 0b1010_1010;

        assert!(set_bits(&mut byte, 0b0011_1000, 3, 0b101).is_ok());
        assert_eq!(byte, 0b1010_1010);

        assert!(set_bits(&mut byte, 0b0011_1000, 3, 0b010).is_ok());
        assert_eq!(byte, 0b1001_0010);

        // Value wider than the mask is rejected and the byte is unchanged
        assert!(set_bits(&mut byte, 0b0011_1000, 3, 0b1000).is_err());
        assert_eq!(byte, 0b1001_0010);
    }

    #[test]
    fn test_set_flag() {
        let mut byte = 0;
        set_flag(&mut byte, 0x10, true);
        assert_eq!(byte, 0x10);
        set_flag(&mut byte, 0x10, true);
        assert_eq!(byte, 0x10);
        set_flag(&mut byte, 0x10, false);
        assert_eq!(byte, 0);

        let mut byte = 0xFF;
        set_flag(&mut byte, 0x10, false);
        assert_eq!(byte, 0xEF);
    }

    // ---------------------------------------------------------------------
    // GtpuHdr: first octet  | Version (3) | PT (1) | * (1) | E (1) | S (1) | PN (1) |
    // ---------------------------------------------------------------------

    #[test]
    fn test_version() {
        let mut hdr = gtpu_hdr();

        // Test with GTP-U version
        assert!(hdr.set_version(GTP_VERSION).is_ok());
        assert_eq!(hdr.version(), 1);
        assert_eq!(hdr.v_pt_flags, 0b0010_0000);

        // Test with zero
        assert!(hdr.set_version(0).is_ok());
        assert_eq!(hdr.version(), 0);
        assert_eq!(hdr.v_pt_flags, 0);

        // Test with max 3-bit value
        assert!(hdr.set_version(7).is_ok());
        assert_eq!(hdr.version(), 7);
        assert_eq!(hdr.v_pt_flags, 0b1110_0000);

        // Values wider than 3 bits are rejected and leave the field unchanged
        assert!(hdr.set_version(8).is_err());
        assert!(hdr.set_version(u8::MAX).is_err());
        assert_eq!(hdr.version(), 7);
        assert_eq!(hdr.v_pt_flags, 0b1110_0000);
    }

    #[test]
    fn test_version_preserves_other_bits() {
        let mut hdr = gtpu_hdr();
        hdr.v_pt_flags = 0b0001_1111; // PT, spare, E, S, PN all set

        assert!(hdr.set_version(GTP_VERSION).is_ok());
        assert_eq!(hdr.version(), 1);
        assert_eq!(hdr.v_pt_flags, 0b0011_1111);
    }

    #[test]
    fn test_protocol_type() {
        let mut hdr = gtpu_hdr();

        // Test with GTP (1)
        assert!(hdr.set_protocol_type(GTP_PROTOCOL_TYPE).is_ok());
        assert_eq!(hdr.protocol_type(), 1);
        assert_eq!(hdr.v_pt_flags, 0b0001_0000);

        // Test with GTP' (0)
        assert!(hdr.set_protocol_type(0).is_ok());
        assert_eq!(hdr.protocol_type(), 0);
        assert_eq!(hdr.v_pt_flags, 0);

        // Values wider than 1 bit must not spill into the version bits
        assert!(hdr.set_protocol_type(2).is_err());
        assert_eq!(hdr.version(), 0);
        assert_eq!(hdr.v_pt_flags, 0);
    }

    #[test]
    fn test_protocol_type_preserves_other_bits() {
        let mut hdr = gtpu_hdr();
        hdr.v_pt_flags = 0xFF;

        assert!(hdr.set_protocol_type(0).is_ok());
        assert_eq!(hdr.protocol_type(), 0);
        assert_eq!(hdr.v_pt_flags, 0b1110_1111);

        assert!(hdr.set_protocol_type(1).is_ok());
        assert_eq!(hdr.v_pt_flags, 0xFF);
    }

    #[test]
    fn test_extension_header_flag() {
        let mut hdr = gtpu_hdr();
        assert!(!hdr.has_extension_header());
        assert!(!hdr.has_flags());

        hdr.set_extension_header(true);
        assert!(hdr.has_extension_header());
        assert!(hdr.has_flags());
        assert_eq!(hdr.v_pt_flags, 0b0000_0100);

        hdr.set_extension_header(false);
        assert!(!hdr.has_extension_header());
        assert!(!hdr.has_flags());
        assert_eq!(hdr.v_pt_flags, 0);
    }

    #[test]
    fn test_sequence_number_flag() {
        let mut hdr = gtpu_hdr();

        hdr.set_sequence_number_flag(true);
        assert!(hdr.has_sequence_number());
        assert!(!hdr.has_npdu_number());
        assert!(!hdr.has_extension_header());
        assert!(hdr.has_flags());
        assert_eq!(hdr.v_pt_flags, 0b0000_0010);

        hdr.set_sequence_number_flag(false);
        assert!(!hdr.has_sequence_number());
        assert_eq!(hdr.v_pt_flags, 0);
    }

    #[test]
    fn test_npdu_number_flag() {
        let mut hdr = gtpu_hdr();

        hdr.set_npdu_number_flag(true);
        assert!(hdr.has_npdu_number());
        assert!(!hdr.has_sequence_number());
        assert!(hdr.has_flags());
        assert_eq!(hdr.v_pt_flags, 0b0000_0001);

        hdr.set_npdu_number_flag(false);
        assert!(!hdr.has_npdu_number());
        assert_eq!(hdr.v_pt_flags, 0);
    }

    #[test]
    fn test_flag_setters_preserve_other_bits() {
        let mut hdr = gtpu_hdr();
        hdr.v_pt_flags = 0xFF;

        hdr.set_extension_header(false);
        assert_eq!(hdr.v_pt_flags, 0b1111_1011);
        hdr.set_sequence_number_flag(false);
        assert_eq!(hdr.v_pt_flags, 0b1111_1001);
        hdr.set_npdu_number_flag(false);
        assert_eq!(hdr.v_pt_flags, 0b1111_1000);

        // Version, PT and spare are untouched
        assert_eq!(hdr.version(), 7);
        assert_eq!(hdr.protocol_type(), 1);
        // Version/PT/spare bits alone do not count as optional-field flags
        assert!(!hdr.has_flags());
    }

    #[test]
    fn test_message_type() {
        let mut hdr = gtpu_hdr();

        hdr.set_message_type(GtpuMessageType::GPdu.into());
        assert_eq!(hdr.message_type(), Ok(GtpuMessageType::GPdu));
        assert_eq!(hdr.msg_type, 0xFF);

        hdr.set_message_type(GtpuMessageType::EchoRequest.into());
        assert_eq!(hdr.message_type(), Ok(GtpuMessageType::EchoRequest));
        assert_eq!(hdr.msg_type, 0x01);

        // Unknown message type is returned as the raw byte
        hdr.set_message_type(42);
        assert_eq!(hdr.message_type(), Err(42));
    }

    #[test]
    fn test_message_length() {
        let mut hdr = gtpu_hdr();

        // Test with a standard value
        let test_len: u16 = 1400;
        hdr.set_message_length(test_len);
        assert_eq!(hdr.message_length(), test_len);

        // Verify byte order in raw storage (big-endian/network byte order)
        assert_eq!(hdr.msg_len, [0x05, 0x78]);

        // Test with zero
        hdr.set_message_length(0);
        assert_eq!(hdr.message_length(), 0);
        assert_eq!(hdr.msg_len, [0, 0]);

        // Test with max value
        hdr.set_message_length(u16::MAX);
        assert_eq!(hdr.message_length(), u16::MAX);
        assert_eq!(hdr.msg_len, [0xFF, 0xFF]);
    }

    #[test]
    fn test_teid() {
        let mut hdr = gtpu_hdr();

        // Test with a standard value
        let test_teid: u32 = 0x1234_5678;
        hdr.set_teid(test_teid);
        assert_eq!(hdr.teid(), test_teid);

        // Verify byte order in raw storage (big-endian/network byte order)
        assert_eq!(hdr.teid, [0x12, 0x34, 0x56, 0x78]);

        // Test with zero
        hdr.set_teid(0);
        assert_eq!(hdr.teid(), 0);
        assert_eq!(hdr.teid, [0, 0, 0, 0]);

        // Test with max value
        hdr.set_teid(u32::MAX);
        assert_eq!(hdr.teid(), u32::MAX);
        assert_eq!(hdr.teid, [0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_setters_do_not_touch_neighbouring_fields() {
        let mut hdr = gtpu_hdr();
        hdr.set_teid(u32::MAX);
        hdr.set_message_type(GtpuMessageType::GPdu.into());

        hdr.set_message_length(0);
        assert_eq!(hdr.msg_type, 0xFF);
        assert_eq!(hdr.teid, [0xFF; 4]);

        hdr.set_teid(0);
        assert_eq!(hdr.msg_len, [0, 0]);
        assert_eq!(hdr.msg_type, 0xFF);
    }

    #[test]
    fn test_gtpu_hdr_wire_format() {
        let mut hdr = gtpu_hdr();
        hdr.set_version(GTP_VERSION).unwrap();
        hdr.set_protocol_type(GTP_PROTOCOL_TYPE).unwrap();
        hdr.set_extension_header(true);
        hdr.set_message_type(GtpuMessageType::GPdu.into());
        hdr.set_message_length(0x0054);
        hdr.set_teid(0x0000_a516);

        // 0x34 = Version 1, PT 1, E 1; 0xFF = G-PDU
        assert_eq!(
            as_bytes(&hdr),
            &[0x34, 0xFF, 0x00, 0x54, 0x00, 0x00, 0xa5, 0x16]
        );
    }

    // ---------------------------------------------------------------------
    // GtpuOptFields
    // ---------------------------------------------------------------------

    #[test]
    fn test_sequence_number() {
        let mut opt = gtpu_opt_fields();
        opt.npdu_num = 0xAA;
        opt.next_ext_hdr_type = 0xBB;

        // Test with a standard value
        opt.set_sequence_number(0x1234);
        assert_eq!(opt.sequence_number(), 0x1234);

        // Verify byte order in raw storage (big-endian/network byte order)
        assert_eq!(opt.seq_number, [0x12, 0x34]);

        // Neighbouring fields must not be read or written
        assert_eq!(opt.npdu_num, 0xAA);
        assert_eq!(opt.next_ext_hdr_type, 0xBB);

        // Test with zero
        opt.set_sequence_number(0);
        assert_eq!(opt.sequence_number(), 0);
        assert_eq!(opt.seq_number, [0, 0]);

        // Test with max value
        opt.set_sequence_number(u16::MAX);
        assert_eq!(opt.sequence_number(), u16::MAX);
        assert_eq!(opt.seq_number, [0xFF, 0xFF]);
    }

    #[test]
    fn test_npdu_number() {
        let mut opt = gtpu_opt_fields();

        opt.set_npdu_number(0x42);
        assert_eq!(opt.npdu_number(), 0x42);
        assert_eq!(opt.npdu_num, 0x42);

        opt.set_npdu_number(u8::MAX);
        assert_eq!(opt.npdu_number(), u8::MAX);
    }

    #[test]
    fn test_next_extension_header_type() {
        let mut opt = gtpu_opt_fields();

        opt.set_next_extension_header(GtpuExtensionType::PduSessionContainer.into());
        assert_eq!(
            opt.next_extension_header_type(),
            Ok(GtpuExtensionType::PduSessionContainer)
        );
        assert_eq!(opt.next_ext_hdr_type, 0x85);

        opt.set_next_extension_header(GtpuExtensionType::NoMoreExtensions.into());
        assert_eq!(
            opt.next_extension_header_type(),
            Ok(GtpuExtensionType::NoMoreExtensions)
        );

        // Unknown extension type is returned as the raw byte
        opt.set_next_extension_header(0x99);
        assert_eq!(opt.next_extension_header_type(), Err(0x99));
    }

    // ---------------------------------------------------------------------
    // DL PDU SESSION INFORMATION (TS 38.415 5.5.2.1)
    // octet 1: | PDU Type (4) | QMP | SNP | MSNP | Spare |
    // octet 2: | PPP | RQI | QFI (6) |
    // ---------------------------------------------------------------------

    #[test]
    fn test_pdu_type() {
        let mut s = DLPduSession::default();

        assert!(s.set_pdu_type(DL_PDU_TYPE).is_ok());
        assert_eq!(s.pdu_type(), 0);
        assert_eq!(s.pt_flags, 0);

        assert!(s.set_pdu_type(UL_PDU_TYPE).is_ok());
        assert_eq!(s.pdu_type(), 1);
        assert_eq!(s.pt_flags, 0b0001_0000);

        // Max 4-bit value
        assert!(s.set_pdu_type(0x0F).is_ok());
        assert_eq!(s.pdu_type(), 0x0F);
        assert_eq!(s.pt_flags, 0b1111_0000);

        // Values wider than 4 bits are rejected and leave the field unchanged
        assert!(s.set_pdu_type(0x10).is_err());
        assert_eq!(s.pdu_type(), 0x0F);
        assert_eq!(s.pt_flags, 0b1111_0000);
    }

    #[test]
    fn test_pdu_type_preserves_flags() {
        let mut s = DLPduSession {
            pt_flags: 0x0F,
            flags_qfi: 0,
        };

        assert!(s.set_pdu_type(1).is_ok());
        assert_eq!(s.pdu_type(), 1);
        assert_eq!(s.pt_flags, 0x1F);
    }

    #[test]
    fn test_qmp() {
        let mut s = DLPduSession::default();

        s.set_qmp(true);
        assert!(s.has_qmp());
        assert_eq!(s.pt_flags, 0b0000_1000);

        s.set_qmp(false);
        assert!(!s.has_qmp());
        assert_eq!(s.pt_flags, 0);
    }

    #[test]
    fn test_snp() {
        let mut s = DLPduSession::default();

        s.set_snp(true);
        assert!(s.has_snp());
        assert_eq!(s.pt_flags, 0b0000_0100);

        s.set_snp(false);
        assert!(!s.has_snp());
        assert_eq!(s.pt_flags, 0);
    }

    #[test]
    fn test_msnp() {
        let mut s = DLPduSession::default();

        s.set_msnp(true);
        assert!(s.has_msnp());
        assert_eq!(s.pt_flags, 0b0000_0010);

        s.set_msnp(false);
        assert!(!s.has_msnp());
        assert_eq!(s.pt_flags, 0);
    }

    #[test]
    fn test_first_octet_flags_preserve_other_bits() {
        let mut s = DLPduSession {
            pt_flags: 0xFF,
            flags_qfi: 0,
        };

        s.set_qmp(false);
        assert_eq!(s.pt_flags, 0b1111_0111);
        s.set_snp(false);
        assert_eq!(s.pt_flags, 0b1111_0011);
        s.set_msnp(false);
        assert_eq!(s.pt_flags, 0b1111_0001);

        // PDU type is untouched by the flag setters
        assert_eq!(s.pdu_type(), 0x0F);
        // Second octet is untouched as well
        assert_eq!(s.flags_qfi, 0);
    }

    #[test]
    fn test_ppp() {
        let mut s = DLPduSession::default();

        s.set_ppp(true);
        assert!(s.has_ppp());
        assert_eq!(s.flags_qfi, 0b1000_0000);

        s.set_ppp(false);
        assert!(!s.has_ppp());
        assert_eq!(s.flags_qfi, 0);

        // PPP lives in the second octet only
        assert_eq!(s.pt_flags, 0);
    }

    #[test]
    fn test_rqi() {
        let mut s = DLPduSession::default();

        s.set_rqi(true);
        assert!(s.has_rqi());
        assert_eq!(s.flags_qfi, 0b0100_0000);

        s.set_rqi(false);
        assert!(!s.has_rqi());
        assert_eq!(s.flags_qfi, 0);
    }

    #[test]
    fn test_qfi() {
        let mut s = DLPduSession::default();

        // Test with a standard value
        assert!(s.set_qfi(9).is_ok());
        assert_eq!(s.qfi(), 9);
        assert_eq!(s.flags_qfi, 0b0000_1001);

        // Test with zero
        assert!(s.set_qfi(0).is_ok());
        assert_eq!(s.qfi(), 0);

        // Test with max 6-bit value
        assert!(s.set_qfi(63).is_ok());
        assert_eq!(s.qfi(), 63);
        assert_eq!(s.flags_qfi, 0b0011_1111);

        // Values wider than 6 bits are rejected and leave the field unchanged
        assert!(s.set_qfi(64).is_err());
        assert!(s.set_qfi(u8::MAX).is_err());
        assert_eq!(s.qfi(), 63);
        assert_eq!(s.flags_qfi, 0b0011_1111);
    }

    #[test]
    fn test_second_octet_setters_preserve_other_bits() {
        let mut s = DLPduSession {
            pt_flags: 0,
            flags_qfi: 0xFF,
        };

        s.set_ppp(false);
        assert!(!s.has_ppp());
        assert!(s.has_rqi());
        assert_eq!(s.qfi(), 63);
        assert_eq!(s.flags_qfi, 0b0111_1111);

        s.flags_qfi = 0xFF;
        s.set_rqi(false);
        assert!(s.has_ppp());
        assert!(!s.has_rqi());
        assert_eq!(s.qfi(), 63);
        assert_eq!(s.flags_qfi, 0b1011_1111);

        s.flags_qfi = 0xFF;
        assert!(s.set_qfi(0).is_ok());
        assert!(s.has_ppp());
        assert!(s.has_rqi());
        assert_eq!(s.flags_qfi, 0b1100_0000);

        // First octet is untouched by the second-octet setters
        assert_eq!(s.pt_flags, 0);
    }

    // ---------------------------------------------------------------------
    // UL PDU SESSION INFORMATION
    // ---------------------------------------------------------------------

    #[test]
    fn test_ul_pdu_session() {
        let s = ULPduSession {
            pt_flags: 0x1F,             // UL PDU type, all flags set
            n39di_nie_qfi: 0b1100_1001, // both flags set, QFI 9
        };
        assert_eq!(s.pdu_type(), UL_PDU_TYPE);
        assert_eq!(s.qfi(), 9);
    }

    // ---------------------------------------------------------------------
    // PDU Session Container extension header
    // ---------------------------------------------------------------------

    #[test]
    fn test_pdu_ext_length() {
        let mut ext = dl_pdu_ext_hdr();

        // One 4-octet unit
        ext.set_length(1);
        assert_eq!(ext.length(), 1);
        assert_eq!(ext.length, 1);

        ext.set_length(u8::MAX);
        assert_eq!(ext.length(), u8::MAX);
    }

    #[test]
    fn test_pdu_ext_content_and_next_type() {
        let mut ext = dl_pdu_ext_hdr();

        let mut content = DLPduSession::default();
        content.set_qfi(5).unwrap();
        content.set_rqi(true);
        ext.set_content(content);
        assert_eq!(ext.content().qfi(), 5);
        assert!(ext.content().has_rqi());

        ext.set_next_extension_header(GtpuExtensionType::NoMoreExtensions.into());
        assert_eq!(
            ext.next_extension_header_type(),
            Ok(GtpuExtensionType::NoMoreExtensions)
        );

        ext.set_next_extension_header(0x99);
        assert_eq!(ext.next_extension_header_type(), Err(0x99));
    }

    #[test]
    fn test_pdu_ext_wire_format() {
        let mut ext = dl_pdu_ext_hdr();

        let mut content = DLPduSession::default();
        content.set_pdu_type(DL_PDU_TYPE).unwrap();
        content.set_qfi(9).unwrap();

        ext.set_length((GtpuDLPduExtensionHdr::LEN / 4) as u8);
        ext.set_content(content);
        ext.set_next_extension_header(GtpuExtensionType::NoMoreExtensions.into());

        // Length 1, DL PDU type 0 with no flags, QFI 9, no more extensions
        assert_eq!(as_bytes(&ext), &[0x01, 0x00, 0x09, 0x00]);
    }

    // ---------------------------------------------------------------------
    // Enum conversions
    // ---------------------------------------------------------------------

    #[test]
    fn test_message_type_conversions() {
        let all = [
            (GtpuMessageType::EchoRequest, 1u8),
            (GtpuMessageType::EchoResponse, 2),
            (GtpuMessageType::ErrorIndication, 26),
            (GtpuMessageType::SupportedExtensionHeaders, 31),
            (GtpuMessageType::TunnelStatus, 253),
            (GtpuMessageType::EndMarker, 254),
            (GtpuMessageType::GPdu, 255),
        ];

        for (ty, byte) in all {
            assert_eq!(u8::from(ty), byte);
            assert_eq!(GtpuMessageType::try_from(byte), Ok(ty));
        }

        assert_eq!(GtpuMessageType::try_from(0), Err(0));
        assert_eq!(GtpuMessageType::try_from(100), Err(100));
    }

    #[test]
    fn test_extension_type_conversions() {
        let all = [
            (GtpuExtensionType::NoMoreExtensions, 0x00u8),
            (GtpuExtensionType::UdpPort, 0x40),
            (GtpuExtensionType::PduSessionContainer, 0x85),
        ];

        for (ty, byte) in all {
            assert_eq!(u8::from(ty), byte);
            assert_eq!(GtpuExtensionType::try_from(byte), Ok(ty));
        }

        assert_eq!(GtpuExtensionType::try_from(0x01), Err(0x01));
    }
}
