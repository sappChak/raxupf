use bitflags::bitflags;

use crate::{SDF_MAP_SIZE, fteid::Fteid};

bitflags! {
    #[repr(transparent)]
    #[derive(Clone, Copy)]
    pub struct PdiMask: u16 {
        const F_TEID           = 1 << 0;
        const UE_IPV4          = 1 << 1;
        const SDF_FILTER        = 1 << 2;
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
pub struct Pdi {
    pdi_mask: PdiMask,
    source_interface: SourceInterface, // source interface is not optional
    fteid: Fteid,
    ue_ipv4_address: u32,
    sdf_ids: [u32; SDF_MAP_SIZE],
}

impl Default for Pdi {
    fn default() -> Self {
        Self::new()
    }
}

impl Pdi {
    pub fn new() -> Self {
        Self {
            pdi_mask: PdiMask::F_TEID,
            source_interface: SourceInterface::Unknown,
            fteid: Fteid::default(),
            ue_ipv4_address: 0,
            sdf_ids: [0; SDF_MAP_SIZE],
        }
    }

    pub fn pdi_mask(&self) -> PdiMask {
        self.pdi_mask
    }

    pub fn source_interface(&self) -> SourceInterface {
        self.source_interface
    }

    pub fn fteid(&self) -> Fteid {
        self.fteid
    }

    pub fn ue_ipv4_address(&self) -> u32 {
        self.ue_ipv4_address
    }

    pub fn sdf_ids(&self) -> &[u32] {
        &self.sdf_ids
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Pdi {}
