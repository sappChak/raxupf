use core::mem;

use network_types::{getter_be, setter_be};

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
