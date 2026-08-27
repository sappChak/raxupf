#[repr(C)]
#[derive(PartialEq, Clone, Copy)]
pub enum GateStatus {
    Open,
    Closed,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct QerInfo {
    dl_gate_status: GateStatus,
    ul_gate_status: GateStatus,
    qfi: u8,
    has_qfi: bool,
    allocated: bool,
}

impl QerInfo {
    pub fn qfi(&self) -> u8 {
        self.qfi
    }

    pub fn is_closed(&self) -> bool {
        self.dl_gate_status == GateStatus::Closed
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
