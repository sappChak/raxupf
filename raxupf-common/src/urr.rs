#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct UrrInfo {
    ul: u64,
    dl: u64,
    allocated: bool,
}

impl UrrInfo {
    pub fn is_allocated(&self) -> bool {
        self.allocated
    }

    pub fn set_allocated(&mut self, allocated: bool) {
        self.allocated = allocated;
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for UrrInfo {}
