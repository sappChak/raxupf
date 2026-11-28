// TODO: add bitflags for possible ipv6 and other flags

use crate::PodBool;

#[repr(transparent)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Teid(u32);

impl Teid {
    pub fn new(teid: u32) -> Self {
        Self(teid)
    }

    pub fn value(&self) -> u32 {
        self.0
    }
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct FteidPod {
    teid: Teid,
    ipv4_address: [u8; 4],
    ipv6_address: [u8; 16],
    v4: PodBool,
    v6: PodBool,
    _pad: [u8; 2],
}

crate::assert_no_padding!(FteidPod: Teid, [u8; 4], [u8; 16], PodBool, PodBool, [u8; 2]);

impl FteidPod {
    pub fn new(
        teid: Teid,
        ipv4_address: [u8; 4],
        ipv6_address: [u8; 16],
        v4: bool,
        v6: bool,
    ) -> Self {
        Self {
            teid,
            ipv4_address,
            ipv6_address,
            v4: v4.into(),
            v6: v6.into(),
            _pad: [0; 2],
        }
    }

    pub fn is_v4(&self) -> bool {
        self.v4.get()
    }

    pub fn is_v6(&self) -> bool {
        self.v6.get()
    }

    pub fn teid(&self) -> Teid {
        self.teid
    }

    pub fn set_teid(&mut self, teid: Teid) {
        self.teid = teid;
    }

    pub fn ipv4_address(&self) -> [u8; 4] {
        self.ipv4_address
    }

    pub fn set_ipv4_address(&mut self, ipv4_address: [u8; 4]) {
        self.v4 = PodBool::TRUE;
        self.ipv4_address = ipv4_address;
    }

    pub fn ipv6_address(&self) -> [u8; 16] {
        self.ipv6_address
    }

    pub fn set_ipv6_address(&mut self, ipv6_address: [u8; 16]) {
        self.v6 = PodBool::TRUE;
        self.ipv6_address = ipv6_address;
    }
}

// SAFETY: repr(C), no padding (checked by assert_no_padding!), and every
// field is valid for any bit pattern.
#[cfg(feature = "user")]
unsafe impl aya::Pod for FteidPod {}
