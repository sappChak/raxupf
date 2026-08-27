use core::mem;

use network_types::{getter_be, setter_be};

#[repr(C)]
pub struct GtpuDLPduExtensionHdr {
    length: u32,
    content: DLPduSession,
    next_ext_hdr_type: u8,
}

#[repr(C)]
pub struct GtpuULPduExtensionHdr {
    length: u32,
    content: ULPduSession,
    next_ext_hdr_type: u8,
}

/// DL PDU SESSION INFORMATION as per 3GPP TS 38.415
#[repr(C)]
#[derive(Default)]
pub struct DLPduSession {
    pt_flags: u8,
    flags_qfi: u8,
}

/// UL PDU SESSION INFORMATION as per 3GPP TS 38.415
#[repr(C)]
pub struct ULPduSession {
    pt_flags: u8,
    n39di_nie_qfi: u8,
}

impl GtpuDLPduExtensionHdr {
    pub const LEN: usize = mem::size_of::<GtpuDLPduExtensionHdr>();

    pub fn length(&self) -> u32 {
        unsafe { getter_be!(self, length, u32) }
    }

    pub fn set_length(&mut self, length: u32) {
        unsafe { setter_be!(self, length, length) }
    }

    pub fn set_content(&mut self, content: DLPduSession) {
        self.content = content
    }

    pub fn set_next_extension_header(&mut self, neh_type: u8) {
        self.next_ext_hdr_type = neh_type;
    }
}

impl DLPduSession {
    pub const LEN: usize = mem::size_of::<DLPduSession>();

    pub fn pdu_type(&self) -> u8 {
        self.pt_flags >> 4
    }

    pub fn set_pdu_type(&mut self, pdu_type: u8) {
        let preserved_bits = self.pt_flags & 0x0F;
        self.pt_flags = (pdu_type << 4) | preserved_bits;
    }

    pub fn has_qmp(&self) -> bool {
        self.pt_flags & 0x08 != 0
    }

    pub fn set_qmp(&mut self, qmp: u8) {
        let preserved_bits = self.pt_flags & 0xF7;
        self.pt_flags = (qmp << 3) | preserved_bits;
    }

    pub fn snp(&self) -> bool {
        self.pt_flags & 0x04 != 0
    }

    pub fn set_snp(&mut self, snp: u8) {
        let preserved_bits = self.pt_flags & 0xFB;
        self.pt_flags = (snp << 2) | preserved_bits;
    }

    pub fn msnp(&self) -> bool {
        self.pt_flags & 0x02 != 0
    }

    pub fn set_msnp(&mut self, msnp: u8) {
        let preserved_bits = self.pt_flags & 0xFD;
        self.pt_flags = (msnp << 1) | preserved_bits;
    }

    pub fn has_ppp(&self) -> bool {
        self.flags_qfi & 0x80 != 0
    }

    pub fn set_ppp(&mut self, ppp: u8) {
        let preserved_bits = self.flags_qfi & 0x3F;
        self.pt_flags = (ppp << 7) | preserved_bits;
    }

    pub fn has_rqi(&self) -> bool {
        self.flags_qfi & 0x40 != 0
    }

    pub fn set_rqi(&mut self, rqi: u8) {
        let preserved_bits = self.flags_qfi & 0xBF;
        self.flags_qfi = (rqi << 6) | preserved_bits;
    }

    pub fn qfi(&self) -> u8 {
        self.flags_qfi & 0x3F
    }

    pub fn set_qfi(&mut self, qfi: u8) {
        let preserved_bits = 0xC0;
        self.flags_qfi = qfi | preserved_bits;
    }
}

impl ULPduSession {
    pub const LEN: usize = mem::size_of::<ULPduSession>();
    pub fn qfi(&self) -> u8 {
        self.n39di_nie_qfi & 0x3F
    }
}
