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
unsafe impl aya::Pod for FibMacs {}
