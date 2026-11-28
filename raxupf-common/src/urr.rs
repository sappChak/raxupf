use crate::PodBool;

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct UrrInfo {
    ul: u64,
    dl: u64,
    allocated: PodBool,
    _pad: [u8; 7],
}

crate::assert_no_padding!(UrrInfo: u64, u64, PodBool, [u8; 7]);

impl UrrInfo {
    pub fn is_allocated(&self) -> bool {
        self.allocated.get()
    }

    pub fn set_allocated(&mut self, allocated: bool) {
        self.allocated = allocated.into();
    }
}

// SAFETY: repr(C), no padding (checked by assert_no_padding!), and every
// field is valid for any bit pattern.
#[cfg(feature = "user")]
unsafe impl aya::Pod for UrrInfo {}
