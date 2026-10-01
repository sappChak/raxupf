#![no_std]

#[cfg(feature = "user")]
use aya::Pod;

pub mod far;
pub mod fteid;
pub mod pdi;
pub mod pdr;
pub mod qer;
pub mod sdf;
pub mod ue_ip;
pub mod urr;

pub const FAR_MAP_SIZE: usize = 10;
pub const QER_MAP_SIZE: usize = 10;
pub const URR_MAP_SIZE: usize = 10;
pub const SDF_MAP_SIZE: usize = 3;
pub const SESSION_MAP_SIZE: usize = 10;
pub const PDR_MAP_SIZE: usize = 10;
pub const MAX_QFI_NUM: usize = 5;

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct FibMacs {
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
}

impl FibMacs {
    pub fn new(src_mac: [u8; 6], dst_mac: [u8; 6]) -> Self {
        Self { src_mac, dst_mac }
    }

    pub fn src_mac(&self) -> [u8; 6] {
        self.src_mac
    }

    pub fn dst_mac(&self) -> [u8; 6] {
        self.dst_mac
    }
}

#[cfg(feature = "user")]
unsafe impl Pod for FibMacs {}
