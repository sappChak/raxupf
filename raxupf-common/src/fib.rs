#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct FibMacs {
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    ifindex: u32,
}

crate::assert_no_padding!(FibMacs: [u8; 6], [u8; 6], u32);

impl FibMacs {
    pub fn new(src_mac: [u8; 6], dst_mac: [u8; 6], ifindex: u32) -> Self {
        Self {
            src_mac,
            dst_mac,
            ifindex,
        }
    }

    pub fn src_mac(&self) -> [u8; 6] {
        self.src_mac
    }

    pub fn dst_mac(&self) -> [u8; 6] {
        self.dst_mac
    }

    pub fn ifindex(&self) -> u32 {
        self.ifindex
    }
}

// SAFETY: repr(C), no padding (checked by assert_no_padding!), and every
// field is valid for any bit pattern.
#[cfg(feature = "user")]
unsafe impl aya::Pod for FibMacs {}
