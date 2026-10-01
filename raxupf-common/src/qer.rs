#[repr(C)]
#[derive(Default, PartialEq, Clone, Copy)]
pub enum GateStatus {
    Open,
    #[default]
    Closed,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
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
#[derive(Default, Clone, Copy)]
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

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct QerInfo {
    dl_gate_status: GateStatus,
    ul_gate_status: GateStatus,
    mbr: Mbr,
    gbr: Gbr,
    qfi: u8,
    has_qfi: bool,
    allocated: bool,
}

impl QerInfo {
    pub fn qfi(&self) -> u8 {
        self.qfi
    }

    pub fn set_qfi(&mut self, qfi: u8) {
        self.has_qfi = true;
        self.qfi = qfi;
    }

    pub fn is_closed(&self, is_uplink: bool) -> bool {
        if is_uplink {
            return self.ul_gate_status == GateStatus::Closed;
        }
        self.dl_gate_status == GateStatus::Closed
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
        self.has_qfi
    }

    pub fn is_allocated(&self) -> bool {
        self.allocated
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for GateStatus {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for QerInfo {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Mbr {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Gbr {}
