// TODO: add bitflags for possible ipv6 and other flags

#[repr(C)]
#[derive(Default, Clone, Copy, PartialEq, Eq)]
pub struct FteidPod {
    teid: u32,
    ipv4_address: u32,
}

impl FteidPod {
    pub fn new(teid: u32, ipv4_address: u32) -> Self {
        Self { teid, ipv4_address }
    }

    pub fn teid(&self) -> u32 {
        self.teid
    }

    pub fn ipv4_address(&self) -> u32 {
        self.ipv4_address
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FteidPod {}
