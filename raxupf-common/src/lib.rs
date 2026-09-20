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
pub const SDF_MAP_SIZE: usize = 10;
pub const SESSION_MAP_SIZE: usize = 10;
pub const PDR_MAP_SIZE: usize = 10;
pub const MAX_QFI_NUM: usize = 5;

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct FibMacs {
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
}

#[cfg(feature = "user")]
unsafe impl Pod for FibMacs {}
