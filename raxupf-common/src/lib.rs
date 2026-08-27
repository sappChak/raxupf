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

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SessionContext {
    ul_pdrs: [PdrInfo; PDR_MAP_SIZE], // sorted by precedence in ascending order
    dl_pdrs: [PdrInfo; PDR_MAP_SIZE],
}

impl SessionContext {
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
unsafe impl Pod for SessionContext {}

#[cfg(feature = "user")]
unsafe impl Pod for FibMacs {}
