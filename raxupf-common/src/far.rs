use bitflags::bitflags;

bitflags! {
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub struct FarAction: u8 {
        const DROP = 1 << 0; // Bit 1
        const FORW = 1 << 1; // Bit 2
        const BUFF = 1 << 2; // Bit 3
        const NOCP = 1 << 3; // Bit 4
        const DUPL = 1 << 4; // Bit 5
    }
}

bitflags! {
    #[repr(transparent)]
    #[derive(Clone, Copy)]
    pub struct OhcFlags: u8 {
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
    flags: OhcFlags,
    teid: u32,
    ipv4_address: u32,
    port_number: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FarInfo {
    destination_interface: u8,
    action: FarAction,
    dscp: u8,
    teid: u32,
    remote_ipv4: u32,
    ohc: OhcFlags,
}

impl Default for FarInfo {
    fn default() -> Self {
        Self::new()
    }
}

impl FarInfo {
    pub fn new() -> Self {
        Self {
            destination_interface: 0,
            action: FarAction::empty(),
            dscp: 0,
            teid: 0,
            remote_ipv4: 0,
            ohc: OhcFlags::empty(),
        }
    }

    pub fn destination_interface(&self) -> u8 {
        self.destination_interface
    }

    pub fn set_destination_interface(&mut self, destination_interface: u8) {
        self.destination_interface = destination_interface;
    }

    pub fn action(&self) -> FarAction {
        self.action
    }

    pub fn set_action(&mut self, action: u8) {
        self.action = FarAction::from_bits_truncate(action);
    }

    pub fn dscp(&self) -> u8 {
        self.dscp
    }

    pub fn set_dscp(&mut self, tos: u8) {
        self.dscp = tos;
    }

    pub fn teid(&self) -> u32 {
        self.teid
    }

    pub fn set_teid(&mut self, teid: u32) {
        self.teid = teid;
    }

    pub fn remote_ipv4(&self) -> u32 {
        self.remote_ipv4
    }

    pub fn set_remote_ipv4(&mut self, remote_ipv4: u32) {
        self.remote_ipv4 = remote_ipv4;
    }

    pub fn ohc(&self) -> OhcFlags {
        self.ohc
    }

    pub fn set_ohc(&mut self, ohc: OhcFlags) {
        self.ohc = ohc;
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for OhcFlags {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FarInfo {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FarAction {}
