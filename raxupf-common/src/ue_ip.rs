use crate::PodBool;

#[repr(C)]
#[derive(PartialEq, Eq, Debug, Default, Clone, Copy)]
pub struct UeIpPod {
    ipv4_address: [u8; 4],
    ipv6_address: [u8; 16],
    v4: PodBool,
    v6: PodBool,
}

crate::assert_no_padding!(UeIpPod: [u8; 4], [u8; 16], PodBool, PodBool);

impl UeIpPod {
    pub fn new(ipv4_addr: u32, ipv6_addr: u128, v4: bool, v6: bool) -> Self {
        Self {
            ipv4_address: ipv4_addr.to_be_bytes(),
            ipv6_address: ipv6_addr.to_be_bytes(),
            v4: v4.into(),
            v6: v6.into(),
        }
    }

    pub fn is_v4(&self) -> bool {
        self.v4.get()
    }

    pub fn is_v6(&self) -> bool {
        self.v6.get()
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
unsafe impl aya::Pod for UeIpPod {}
