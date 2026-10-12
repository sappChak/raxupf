#![no_std]

pub mod far;
pub mod fib;
pub mod fteid;
pub mod pdi;
pub mod pdr;
pub mod qer;
pub mod sdf;
pub mod ue_ip;
pub mod urr;

pub const FAR_MAP_SIZE: usize = 10;
pub const QER_MAP_SIZE: usize = 10;
pub const MAX_QFI_NUM: usize = 10;
pub const URR_MAP_SIZE: usize = 10;
pub const SDF_MAP_SIZE: usize = 10;
pub const PDR_MAP_SIZE: usize = 10;

pub const PROG_GTP: u32 = 0;
pub const PROG_N6: u32 = 1;
