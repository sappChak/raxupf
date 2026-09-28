// TODO: add bitflags for possible ipv6 and other flags

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct FteidPod {
    teid: u32,
    v4: bool,
    v6: bool,
    ipv4_address: u32,
    ipv6_address: [u8; 16],
}

impl FteidPod {
    pub fn new(teid: u32, ipv4_address: u32, ipv6_address: [u8; 16], v4: bool, v6: bool) -> Self {
        Self {
            teid,
            ipv4_address,
            ipv6_address,
            v4,
            v6,
        }
    }

    pub fn is_v4(&self) -> bool {
        self.v4
    }

    pub fn is_v6(&self) -> bool {
        self.v6
    }

    pub fn teid(&self) -> u32 {
        self.teid
    }

    pub fn set_teid(&mut self, teid: u32) {
        self.teid = teid;
    }

    pub fn ipv4_address(&self) -> u32 {
        self.ipv4_address
    }

    pub fn set_ipv4_address(&mut self, ipv4_address: u32) {
        self.v4 = true;
        self.ipv4_address = ipv4_address;
    }

    pub fn ipv6_address(&self) -> [u8; 16] {
        self.ipv6_address
    }

    pub fn set_ipv6_address(&mut self, ipv6_address: [u8; 16]) {
        self.v6 = true;
        self.ipv6_address = ipv6_address;
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FteidPod {}
