use bitflags::bitflags;

use crate::{MAX_QFI_NUM, SDF_MAP_SIZE, fteid::FteidPod, sdf::SdfFilterPod, ue_ip::UeIpPod};

bitflags! {
    #[repr(transparent)]
    #[derive(PartialEq, Eq, Debug, Clone, Copy)]
    pub struct PdiMask: u16 {
        const F_TEID = 1 << 0;
        const UE_IP = 1 << 1;
        const SDF_FILTER = 1 << 2;
        const QFI = 1 << 3;
    }
}

bitflags! {
    #[repr(transparent)]
    #[derive(PartialEq, Eq, Debug, Clone, Copy)]
    pub struct SourceInterfacePod: u8 {
        const ACCESS = 1 << 0;
        const CORE = 1 << 1;
        const SGI_LAN = 1 << 2;
        const CP_FUNCTION = 1 << 3;
        const UNKNOWN = 1 << 4;
    }
}

#[repr(C)]
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub struct PdiPod {
    pub pdi_mask: PdiMask,
    pub source_interface: SourceInterfacePod,
    pub fteid: FteidPod,
    pub ue_ip_address: UeIpPod,
    pub qfis: [u8; MAX_QFI_NUM],
    pub sdfs: [SdfFilterPod; SDF_MAP_SIZE],
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
            source_interface: SourceInterfacePod::empty(),
            fteid: FteidPod::default(),
            ue_ip_address: UeIpPod::default(),
            qfis: [0; MAX_QFI_NUM],
            sdfs: [SdfFilterPod::default(); SDF_MAP_SIZE],
        }
    }

    pub fn pdi_mask(&self) -> &PdiMask {
        &self.pdi_mask
    }

    pub fn set_flag(&mut self, flag: PdiMask) {
        self.pdi_mask |= flag;
    }

    pub fn source_interface(&self) -> SourceInterfacePod {
        self.source_interface
    }

    pub fn set_source_interface(&mut self, source: SourceInterfacePod) {
        self.source_interface = source;
    }

    pub fn fteid(&self) -> FteidPod {
        self.fteid
    }

    pub fn set_fteid(&mut self, fteid: FteidPod) {
        self.set_flag(PdiMask::F_TEID);
        self.fteid = fteid;
    }

    pub fn ue_ip_address(&self) -> &UeIpPod {
        &self.ue_ip_address
    }

    pub fn set_ue_ip_address(&mut self, ue_ip_address: UeIpPod) {
        self.set_flag(PdiMask::UE_IP);
        self.ue_ip_address = ue_ip_address;
    }

    pub fn qfis(&self) -> &[u8; MAX_QFI_NUM] {
        &self.qfis
    }

    pub fn set_qfi(&mut self, idx: usize, qfi: u8) {
        self.set_flag(PdiMask::QFI);
        self.qfis[idx] = qfi;
    }

    pub fn sdfs(&self) -> &[SdfFilterPod; SDF_MAP_SIZE] {
        &self.sdfs
    }

    pub fn set_sdf(&mut self, idx: usize, sdf: SdfFilterPod) {
        self.sdfs[idx] = sdf;
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PdiPod {}
