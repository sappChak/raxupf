use bitflags::bitflags;

use crate::{MAX_QFI_NUM, SDF_MAP_SIZE, fteid::FteidPod, sdf::SdfFilterPod, ue_ip::UeIpPod};

bitflags! {
    #[repr(transparent)]
    #[derive(Clone, Copy)]
    pub struct PdiMask: u16 {
        const F_TEID = 1 << 0;
        const UE_IP = 1 << 1;
        const SDF_FILTER = 1 << 2;
        const QFI = 1 << 3;
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceInterface {
    Access = 0,
    Core = 1,
    SgiLan = 2,
    CpFunction = 3,
    Unknown,
}

impl From<u8> for SourceInterface {
    fn from(v: u8) -> Self {
        match v {
            0 => SourceInterface::Access,
            1 => SourceInterface::Core,
            2 => SourceInterface::SgiLan,
            3 => SourceInterface::CpFunction,
            _ => SourceInterface::Unknown,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PdiPod {
    pdi_mask: PdiMask,
    source_interface: u8,
    fteid: FteidPod,
    ue_ip_address: UeIpPod,
    qfis: [u8; MAX_QFI_NUM],
    sdfs: [SdfFilterPod; SDF_MAP_SIZE],
}

impl Default for PdiPod {
    fn default() -> Self {
        Self::new()
    }
}

impl PdiPod {
    pub fn new() -> Self {
        Self {
            pdi_mask: PdiMask::empty(),
            source_interface: 0,
            fteid: FteidPod::default(),
            ue_ip_address: UeIpPod::default(),
            qfis: [0; MAX_QFI_NUM],
            sdfs: [SdfFilterPod::default(); SDF_MAP_SIZE],
        }
    }

    pub fn pdi_mask(&self) -> PdiMask {
        self.pdi_mask
    }

    pub fn set_flag(&mut self, flag: PdiMask) {
        self.pdi_mask |= flag;
    }

    pub fn source_interface(&self) -> SourceInterface {
        SourceInterface::from(self.source_interface)
    }

    pub fn set_source_interface(&mut self, source_interface: u8) {
        self.source_interface = source_interface;
    }

    pub fn fteid(&self) -> FteidPod {
        self.fteid
    }

    pub fn set_fteid(&mut self, fteid: FteidPod) {
        self.fteid = fteid;
        self.set_flag(PdiMask::F_TEID);
    }

    pub fn ue_ip_address(&self) -> UeIpPod {
        self.ue_ip_address
    }

    pub fn set_ue_ip_address(&mut self, ue_ip_address: UeIpPod) {
        self.ue_ip_address = ue_ip_address;
        self.set_flag(PdiMask::UE_IP);
    }

    pub fn qfis(&self) -> &[u8] {
        &self.qfis
    }

    pub fn set_qfi(&mut self, idx: usize, qfi: u8) {
        self.qfis[idx] = qfi;
        self.set_flag(PdiMask::QFI);
    }

    pub fn sdfs(&self) -> &[SdfFilterPod] {
        &self.sdfs
    }

    pub fn set_sdf(&mut self, idx: usize, sdf: SdfFilterPod) {
        self.sdfs[idx] = sdf;
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PdiPod {}
