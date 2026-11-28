use crate::PodBool;

/// Gate status as per 3GPP TS 29.244, 8.2.7 (0 = OPEN, 1 = CLOSED).
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GateStatus(u8);

impl GateStatus {
    pub const OPEN: Self = Self(0);
    pub const CLOSED: Self = Self(1);

    #[inline(always)]
    pub fn is_open(self) -> bool {
        self == Self::OPEN
    }
}

impl Default for GateStatus {
    fn default() -> Self {
        Self::CLOSED
    }
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct Mbr {
    /// Uplink maximum bitrate in kbit/s.
    pub uplink: u64,
    /// Downlink maximum bitrate in kbit/s.
    pub downlink: u64,
}

impl Mbr {
    pub fn new(uplink: u64, downlink: u64) -> Self {
        Self { uplink, downlink }
    }
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct Gbr {
    /// Uplink guaranteed bitrate in kbit/s.
    pub uplink: u64,
    /// Downlink guaranteed bitrate in kbit/s.
    pub downlink: u64,
}

impl Gbr {
    pub fn new(uplink: u64, downlink: u64) -> Self {
        Self { uplink, downlink }
    }
}

crate::assert_no_padding!(Mbr: u64, u64);
crate::assert_no_padding!(Gbr: u64, u64);

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct QerInfo {
    mbr: Mbr,
    gbr: Gbr,
    dl_gate_status: GateStatus,
    ul_gate_status: GateStatus,
    qfi: u8,
    has_qfi: PodBool,
    allocated: PodBool,
    _pad: [u8; 3],
}

crate::assert_no_padding!(QerInfo:
    Mbr, Gbr, GateStatus, GateStatus, u8, PodBool, PodBool, [u8; 3]
);

impl QerInfo {
    pub fn qfi(&self) -> u8 {
        self.qfi
    }

    pub fn set_qfi(&mut self, qfi: u8) {
        self.has_qfi = PodBool::TRUE;
        self.qfi = qfi;
    }

    pub fn is_closed(&self, is_uplink: bool) -> bool {
        if is_uplink {
            return !self.ul_gate_status.is_open();
        }
        !self.dl_gate_status.is_open()
    }

    pub fn set_dl_gate_status(&mut self, gate_status: GateStatus) {
        self.dl_gate_status = gate_status;
    }

    pub fn set_ul_gate_status(&mut self, gate_status: GateStatus) {
        self.ul_gate_status = gate_status;
    }

    pub fn set_mbr(&mut self, mbr: Mbr) {
        self.mbr = mbr;
    }

    pub fn set_gbr(&mut self, gbr: Gbr) {
        self.gbr = gbr;
    }

    pub fn has_qfi(&self) -> bool {
        self.has_qfi.get()
    }

    pub fn is_allocated(&self) -> bool {
        self.allocated.get()
    }

    pub fn set_allocated(&mut self, allocated: bool) {
        self.allocated = allocated.into();
    }
}

// SAFETY: repr(transparent) over u8; every byte value is a valid GateStatus.
#[cfg(feature = "user")]
unsafe impl aya::Pod for GateStatus {}

// SAFETY (QerInfo, Mbr, Gbr): repr(C), no padding (checked by
// assert_no_padding!), and every field is valid for any bit pattern.
#[cfg(feature = "user")]
unsafe impl aya::Pod for QerInfo {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Mbr {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Gbr {}
