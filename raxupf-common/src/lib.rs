#![no_std]

#[cfg(feature = "user")]
use aya::Pod;

pub mod far;
pub mod fteid;
pub mod pdi;
pub mod pdr;
pub mod qer;
pub mod sdf;
pub mod urr;

use crate::pdr::PdrInfo;

pub const FAR_MAP_SIZE: usize = 10;
pub const QER_MAP_SIZE: usize = 10;
pub const URR_MAP_SIZE: usize = 10;
pub const SDF_MAP_SIZE: usize = 10;
pub const SESSION_MAP_SIZE: usize = 10;
pub const PDR_MAP_SIZE: usize = 10;
pub const MAX_QFI_NUM: usize = 5;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SessionContextPod {
    ul_pdrs: [PdrInfo; PDR_MAP_SIZE], // sorted by precedence in ascending order
    dl_pdrs: [PdrInfo; PDR_MAP_SIZE],
}

impl SessionContextPod {
    pub fn new(ul_pdrs: [PdrInfo; PDR_MAP_SIZE], dl_pdrs: [PdrInfo; PDR_MAP_SIZE]) -> Self {
        Self { ul_pdrs, dl_pdrs }
    }
    pub fn downlink_pdrs(&self) -> &[PdrInfo] {
        &self.dl_pdrs
    }

    pub fn uplink_pdrs(&self) -> &[PdrInfo] {
        &self.ul_pdrs
    }
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct FibMacs {
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
}

#[cfg(feature = "user")]
unsafe impl Pod for SessionContextPod {}

#[cfg(feature = "user")]
unsafe impl Pod for FibMacs {}
