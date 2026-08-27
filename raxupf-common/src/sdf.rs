#[repr(C)]
#[derive(Clone, Copy)]
pub struct SdfFilter {
    protocol: u8,
    src_addr: u32,
    dst_addr: u32,
    // src port range
    // dst port range
    allocated: bool,
}

impl SdfFilter {
    pub fn is_allocated(&self) -> bool {
        self.allocated
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SdfFilter {}
