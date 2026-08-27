use bitflags::bitflags;

#[repr(C)]
#[derive(Clone, Copy)]
pub enum FarAction {
    DROP, // Bit 1
    FORW, // Bit 2
    BUFF, // Bit 3
    NOCP, // Bit 4
    DUPL, // Bit 5
}

bitflags! {
    #[repr(transparent)]
    #[derive(Clone, Copy)]
    pub struct OuterHeaderCreationFlags: u8 {
        const GTPU_UDP_IPV4 = 1 << 0;
        const GTPU_UDP_IPV6 = 1 << 1;
        const UDP_IPV4 = 1 << 2;
        const UDP_IPV6 = 1 << 3;
        const IPV4 = 1 << 4;
        const IPV6 = 1 << 5;
        const CTAG = 1 << 6;
        const STAG = 1 << 7;

    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct OuterHeaderCreation {
    flags: OuterHeaderCreationFlags,
    teid: u32,
    ipv4_address: u32,
    port_number: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FarInfo {
    action: FarAction,
    tos: u8,
    teid: u32,
    remote_ip: u32,
    outer_header_creation: OuterHeaderCreationFlags,
}

impl FarInfo {
    pub fn action(&self) -> FarAction {
        self.action
    }

    pub fn tos(&self) -> u8 {
        self.tos
    }

    pub fn teid(&self) -> u32 {
        self.teid
    }

    pub fn remote_ip(&self) -> u32 {
        self.remote_ip
    }

    pub fn ohc(&self) -> OuterHeaderCreationFlags {
        self.outer_header_creation
    }

    pub fn set_ohc(&mut self, ohc: OuterHeaderCreationFlags) {
        self.outer_header_creation = ohc;
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for OuterHeaderCreationFlags {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FarInfo {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FarAction {}
